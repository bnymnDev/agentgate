# Architecture

## The shape of it

```
        MCP host                    agentgate                        upstreams
   ┌─────────────────┐        ┌───────────────────────┐        ┌──────────────────┐
   │                 │        │  mcp.Server           │        │  mcp.Client  ×N  │
   │  your editor    │ stdio  │  ┌─────────────────┐  │ stdio  │  ┌────────────┐  │
   │  your agent     │◀──────▶│  │ receiving       │  │◀──────▶│  │ filesystem │  │
   │  …any MCP host  │  http  │  │ middleware      │  │  http  │  │ github     │  │
   │                 │        │  └────────┬────────┘  │        │  │ your own   │  │
   └─────────────────┘        │           │           │        │  └────────────┘  │
                              │   tools/call only     │        └──────────────────┘
                              │           ▼           │
                              │  ┌─────────────────┐  │
                              │  │ policy.Evaluate │  │  pure: no I/O, no clock
                              │  └────────┬────────┘  │
                              │     allow │ deny/ask  │
                              │           ▼           │
                              │  ┌─────────────────┐  │
                              │  │ audit (async)   │──┼──▶ ~/.agentgate/audit.db
                              │  └─────────────────┘  │
                              └───────────────────────┘
```

Both sides are the official [Go MCP SDK][sdk]. Downstream agentgate *is* an MCP
server; upstream it *is* an MCP client. There is no hand-rolled protocol code,
so anything the SDK learns, agentgate learns.

[sdk]: https://github.com/modelcontextprotocol/go-sdk

## Packages

| Package | Responsibility |
|---|---|
| `internal/config` | Load, expand and validate `agentgate.yaml`, packs included. Every problem reported at once. |
| `internal/policy` | The rule model, the evaluator, label rules, packs, lint, and the session tracker. Pure; no imports outside the standard library and YAML. |
| `internal/packs` | The policy packs that ship with agentgate, embedded YAML. |
| `internal/audit` | SQLite store, migrations, the hash chain, catalog snapshots, redaction, canonical hashing, retention. |
| `internal/proxy` | The MCP passthrough, the interception point, approvals (terminal, web, phone), honeypots, canaries, pinning, webhooks. |
| `internal/pinning` | The lockfile of tool definitions and the definition scan. |
| `internal/canary` | Canary generation, the store, and the detector that sees through encodings. |
| `internal/telemetry` | The OTLP/HTTP span exporter. |
| `internal/killswitch` | The freeze marker: engage, release, status. A file, on purpose. |
| `internal/replay` | Re-evaluate and re-send recorded sessions; align and compare two of them. |
| `internal/mock` | Serve a recorded session as an MCP server. |
| `internal/install` | Find MCP hosts and put agentgate in front of their servers, and take it out again. |
| `internal/ui` | Server-rendered web UI. Templates and assets embedded. |
| `internal/cli` | The cobra command tree. |
| `internal/testserver` | A real demo MCP server used by `make dev`, the e2e test and the proxy tests. |

The dependency graph runs one way: `cli → proxy/ui/replay → audit → policy →
config`. `policy` depends on nothing of ours, which is what keeps it testable
with golden files.

## How a call flows

1. The host sends `tools/call` for `fs__write_file`.
2. The SDK dispatches to the handler agentgate registered for that name. The
   handler already knows which upstream owns it, so there is no name parsing on
   the hot path.
3. The arguments are decoded into a `map[string]any` with `json.Number`, so a
   `gt` comparison sees the number the host actually sent. The session's
   tracker is snapshotted — calls so far, calls in the last minute, the
   identical-call streak, tokens so far, the labels the session carries and the
   tools it has called — the kill-switch marker is checked, and the host, the
   tool's annotations and the current time are attached. Everything the
   evaluator needs is on the `Call`; the evaluator itself touches nothing else.
4. The arguments are searched for canaries — raw, and as decoded strings, so an
   escape does not hide one. A hit ends the call here with rule `canary`,
   whatever the policy says.
5. `policy.Evaluate` returns a `Decision` — an action, a reason, and the id of
   the rule that decided. Never a bare boolean. The kill switch, the loop guard
   and the budgets decide first, with fixed rule ids; then the rules; then the
   default.
6. In **shadow mode** a deny or ask is recorded as such, flagged, and turned into
   an allow — unless the gateway is frozen. Otherwise:
   **deny** → agentgate answers with `CallToolResult{IsError: true}` carrying
   `agentgate denied: <reason> (rule <id>)`. Not a transport error: the agent has
   to be able to read why and adapt.
   **ask** → the call parks until a human answers or the timeout expires.
   **allow** → the call is forwarded with the same arguments, the same `_meta`
   and the same progress token, under a deadline.
7. The result is inspected as it came: a canary in it labels the session
   `canary-read`, hidden text or instructions aimed at the model label it
   `injection-suspected`. Then it goes back untouched — unless `redact_results`
   or `strip_invisible` is on, in which case its text is changed before the
   agent reads it. The label rules are applied, the session's tracker is
   advanced, a record is queued for the audit store and a span for telemetry,
   any webhook that wants to know is told, and the call returns.

Honeypot tools take a shorter path: their handler never consults the policy.
It denies, records with the rule id `honeypot`, notifies, and if configured
engages the kill switch — see [guardrails.md](guardrails.md). A call to a tool
pinning has quarantined never reaches a handler either: the middleware answers
it with rule `quarantine`.

The catalog is built the same way on start and on every `list_changed` an
upstream sends: list the tools, compare each definition with the lockfile and
scan it, hold back what is quarantined, register the rest, and store a
snapshot of the catalog in the audit log so replay and `mock` see what the
session saw.

## What is intercepted, and what is not

Only `tools/call` is subject to policy. Everything else is served from the
merged catalogue or forwarded:

| Method | Handling |
|---|---|
| `tools/list` | Merged across upstreams, prefixed, checked against the lockfile, served by the SDK (so pagination and `list_changed` come for free). A quarantined tool is not listed. |
| `tools/call` | Intercepted. This is the whole product. |
| `resources/*`, `prompts/*` | Registered from every upstream and routed to the one that listed the item. |
| `completion/complete` | Routed by the prompt name or resource URI it refers to. |
| `resources/subscribe` | Routed to the upstream that owns the URI. |
| `logging/setLevel` | Applied locally and forwarded to every upstream, so their log messages honour it. |
| `ping` | Answered locally. |
| `initialize`, `server/discover` | Answered by the SDK from the merged capabilities. An `initialize` opens the audit session; a stateless `server/discover` does not — the session is opened by the first call made on it. |
| `roots/list` | Mirrored: the host's roots are pushed onto every upstream client. |
| everything else | Handled by the SDK. |

### Where the spec was refined

The simple rule for a request with no tool name in it would be "send it to the
first upstream". Taken literally that means a two-upstream setup can only ever
read the first server's resources, so instead:

- `resources/list`, `resources/templates/list` and `prompts/list` are **merged**
  across upstreams. With one upstream — the common case — a merge and a
  passthrough are the same thing.
- `resources/read` and `prompts/get` are routed to the upstream that listed the
  item. A URI no upstream listed (a server serving something outside its own
  template) falls back to trying the upstreams in config order.
- Only `completion/complete` with an unrecognisable reference still falls back to
  the first upstream that supports it.

Name collisions between upstreams are resolved for tools by prefixing. For
resources and prompts, which are not prefixed, the first upstream to claim a
URI or a name keeps it, and the clash is logged.

## Transparency

With one upstream and no matching rule, what the host sees is what the server
sent. Tool schemas are passed through as the SDK decoded them and are never
rewritten. The only thing agentgate changes on a successful call is the tool's
*name*, and only when prefixing is on — plus, when you turn them on, result
redaction and `strip_invisible`, and the tools pinning holds back.

The proxy tests assert this over a real in-process MCP connection: structured
results, resources, prompts and pings all round-trip unchanged.

## Auditing is best effort, on purpose

`Store.RecordCall` snapshots the record on the calling goroutine — redaction,
truncation and hashing all happen there, so the record cannot be changed
underneath it — and then hands it to a buffered channel. A single writer
goroutine drains that channel with its own timeout, because a write must not
inherit the context of a call that has already returned.

If the queue is full, the record is dropped and counted. If the database is
broken, the failure is logged. Neither ever reaches the tool call. An audit log
that can take the gateway down is worse than one with a hole in it.

The database uses one connection (`SetMaxOpenConns(1)`) with WAL. SQLite takes
exactly one writer, and the query volume here does not justify anything cleverer.

### Redaction

A redaction pattern is applied in two places:

- against a synthetic `key: value` probe for every object member, **anchored at
  the start** — a match there replaces the whole value. This is what turns
  `{"api_key": "sk-live-…"}` into `{"api_key": "[REDACTED]"}`.
- against every string value on its own, unanchored — only the match is
  replaced. This is what turns `{"command": "curl -H token=abc"}` into
  `{"command": "curl -H [REDACTED]"}`.

The anchor is the important part: without it, the second document would lose its
whole command, because the pattern matches somewhere inside the value.

Keys are never rewritten and the document is re-serialised from a parsed tree,
so the stored value is always valid JSON — something a regex over the serialised
document could not promise. Hashes are taken **after** redaction, so a call
always hashes the same way regardless of what the redaction rules were when it
ran.

### The hash chain

The writer appends each call as the next link of a chain: a sequence number,
the previous link's hash, and `sha256(previous hash, "\n", every stored column
as JSON)`. The head is read and the link written in one `BEGIN IMMEDIATE`
transaction, which holds SQLite's write lock throughout, so several agentgate
processes sharing a database still build one chain. Retention deletes from the
front of the chain only — a call still within the retention period keeps every
later link — and keeps the last deleted link as the anchor the rest verifies
against. Rows written before the chain existed are counted by `verify` and
otherwise left alone.

## Sessions and budgets

A session is one downstream connection, identified by a ULID (so sorting by id
sorts by time). Its state lives in a `policy.Tracker` in memory on the proxy,
not in the audit store, so budgets and labels keep working with
`audit.enabled: false`. Replay walks a recorded session with the same tracker,
which is how a replayed decision sees what the live one saw.

Session teardown hangs off `ServerSession.Wait`, which returns when the host
disconnects; shutdown closes every session, so that goroutine always has an
exit.

## Concurrency and shutdown

- One goroutine per downstream session, waiting for it to end.
- One goroutine draining the audit queue.
- One goroutine per catalogue refresh triggered by an upstream's `list_changed`;
  refreshes are serialised so two upstreams changing at once cannot interleave.
- One goroutine per webhook delivery, with a ten-second deadline.
- One goroutine per terminal, reading approval answers, so a question that
  timed out cannot swallow the answer to the next one.
- With phone approvals, one goroutine holding the subscription to the answers
  topic, reconnecting with backoff; a question asked on several channels runs
  one goroutine per channel until the first answer.
- One goroutine polling the lockfile for changes made from outside.
- With telemetry, one goroutine batching and exporting spans.

All of them are tracked by a `WaitGroup` and end when `Proxy.Close` runs.
`agentgate run` ties the MCP server, the web UI and signal handling together in
a small run group: when one stops, the others are told to, and the process
returns only once everything is down.

## Known limits

- Roots are mirrored from the most recent downstream session. agentgate is meant
  to sit in front of a single host; with several connected at once the last one
  wins.
- Progress notifications from an upstream are broadcast to every downstream
  session rather than routed to the one that made the call.
- The web UI has no authentication. It refuses to bind to a non-loopback address
  unless you pass `--allow-remote-ui`.
- Pinning trusts on first use. A server that is poisoned on the day it is
  added is pinned poisoned; the definition scan is what stands between that
  and the model, and a scan is a set of heuristics, not a proof.
- A canary is found in the encodings listed in
  [guardrails.md](guardrails.md#canaries). A model split across several calls,
  or one that re-encodes a secret some way nobody listed, can get a fragment
  past it. Pair canaries with the `lethal-trifecta` pack, which asks before the
  session can send anything at all.
