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
| `internal/config` | Load, expand and validate `agentgate.yaml`. Every problem reported at once. |
| `internal/policy` | The rule model and the evaluator. Pure; no imports outside the standard library and YAML. |
| `internal/audit` | SQLite store, migrations, redaction, canonical hashing, retention. |
| `internal/proxy` | The MCP passthrough, the interception point, approvals, honeypots, webhooks. |
| `internal/killswitch` | The freeze marker: engage, release, status. A file, on purpose. |
| `internal/replay` | Re-evaluate and re-send recorded sessions; align and compare two of them. |
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
   counters — calls so far, calls in the last minute, the identical-call streak,
   tokens so far — are snapshotted, the kill-switch marker is checked, and the
   tool's annotations and the current time are attached. Everything the
   evaluator needs is on the `Call`; the evaluator itself touches nothing else.
4. `policy.Evaluate` returns a `Decision` — an action, a reason, and the id of
   the rule that decided. Never a bare boolean. The kill switch, the loop guard
   and the budgets decide first, with fixed rule ids; then the rules; then the
   default.
5. In **shadow mode** a deny or ask is recorded as such, flagged, and turned into
   an allow. Otherwise:
   **deny** → agentgate answers with `CallToolResult{IsError: true}` carrying
   `agentgate denied: <reason> (rule <id>)`. Not a transport error: the agent has
   to be able to read why and adapt.
   **ask** → the call parks until a human answers or the timeout expires.
   **allow** → the call is forwarded with the same arguments, the same `_meta`
   and the same progress token, under a deadline.
6. The result comes back untouched — unless `redact_results` is on, in which
   case its text is scrubbed before the agent reads it. A record is queued for
   the audit store, the session's counters are advanced, any webhook that wants
   to know is told, and the call returns.

Honeypot tools take a shorter path: their handler never consults the policy.
It denies, records with the rule id `honeypot`, notifies, and if configured
engages the kill switch — see [guardrails.md](guardrails.md).

## What is intercepted, and what is not

Only `tools/call` is subject to policy. Everything else is served from the
merged catalogue or forwarded:

| Method | Handling |
|---|---|
| `tools/list` | Merged across upstreams, prefixed, served by the SDK (so pagination and `list_changed` come for free). |
| `tools/call` | Intercepted. This is the whole product. |
| `resources/*`, `prompts/*` | Registered from every upstream and routed to the one that listed the item. |
| `completion/complete` | Routed by the prompt name or resource URI it refers to. |
| `resources/subscribe` | Routed to the upstream that owns the URI. |
| `logging/setLevel` | Applied locally and forwarded to every upstream, so their log messages honour it. |
| `ping` | Answered locally. |
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
resources and prompts, which v0.1 does not prefix, the first upstream to claim a
URI or a name keeps it, and the clash is logged.

## Transparency

With one upstream and no matching rule, what the host sees is what the server
sent. Tool schemas are passed through as the SDK decoded them and are never
rewritten. The only thing agentgate changes on a successful call is the tool's
*name*, and only when prefixing is on.

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

## Sessions and budgets

A session is one downstream connection, identified by a ULID (so sorting by id
sorts by time). Call counters live in memory on the proxy, not in the audit
store, so budgets keep working with `audit.enabled: false`.

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

All of them are tracked by a `WaitGroup` and end when `Proxy.Close` runs.
`agentgate run` ties the MCP server, the web UI and signal handling together in
a small run group: when one stops, the others are told to, and the process
returns only once everything is down.

## Known limits in v0.1

- Roots are mirrored from the most recent downstream session. agentgate is meant
  to sit in front of a single host; with several connected at once the last one
  wins.
- Progress notifications from an upstream are broadcast to every downstream
  session rather than routed to the one that made the call.
- The web UI has no authentication. It refuses to bind to a non-loopback address
  unless you pass `--allow-remote-ui`.
