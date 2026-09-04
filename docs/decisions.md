# Decisions

The questions the design left open, and how they were answered. Each entry says
what was decided, why, and what would change it.

## Prefix separator: `.` or `__`?

**`__`, configurable via `prefix_separator`, with rule patterns tolerant of
both.**

The MCP specification does not restrict tool-name characters. Several hosts do,
having inherited the OpenAI function-calling constraint of
`^[a-zA-Z0-9_-]{1,64}$`, in which a dot is invalid. Picking the character that
works everywhere costs nothing.

The interesting part is that it does not have to be a choice the policy author
lives with. A rule pattern is matched against **both** the exposed name and the
canonical `upstream.tool` spelling, so

```yaml
tool: "fs.write_file"
```

matches `fs__write_file`, `fs.write_file` and whatever else `prefix_separator`
is set to. A policy written with either spelling works verbatim, and changing
the separator never invalidates one.

**Would change it:** hosts converging on a character that reads better. The
config field is already there.

## Should `ask` in stdio mode wait for a UI approval instead of denying?

**Yes, when there is something to wait for. Configurable, and never silent.**

`approval.mode` decides:

| Mode | Behaviour |
|---|---|
| `auto` (default) | web UI if it is running → controlling terminal if there is one → deny |
| `ui` | web UI only |
| `tty` | terminal only |
| `deny` | never ask |

Two things made this better than SPEC's fallback:

- **`/dev/tty` works in stdio mode.** stdin and stdout carry MCP traffic, but the
  *controlling terminal* is still open. agentgate opens it directly (`CONIN$` on
  Windows), so `agentgate run --stdio` launched from a terminal can still prompt.
- **A denial always says which channel was missing** — `approval required, no
  TTY`, `approval required, the web UI is not running`. A policy that says "ask"
  and silently means "deny" is worse than one that says "deny".

An unanswered approval is denied after `approval.timeout` (60 s by default).
Fail closed.

## Result-size cap in the audit database

**256 KB per result, truncated with a flag, and the hash is of the whole thing.**

`audit.max_result_bytes` defaults to 262144. A result over the cap is replaced
with a JSON object carrying the original byte count and the leading bytes:

```json
{"_agentgate_truncated": true, "_agentgate_bytes": 4194304, "head": "…"}
```

Two details that matter:

- **The stored value stays valid JSON.** Slicing a document in half would break
  every consumer — the UI, the diff, the replay report.
- **`result_hash` is computed before truncation**, so a truncated result still
  identifies itself exactly, and `replay` can compare it. `replay` marks such
  calls rather than comparing bodies, because the body is not the whole answer.

## Where do budgets sit relative to rules?

**Before them. A budget is a hard cap no rule can lift.**

The alternative — rules first, so an explicit `allow` beats a budget — makes the
budget advisory, and an advisory cap on a runaway agent is not a cap. The golden
file `testdata/golden/budgets.golden` pins this: a tool with an explicit
`action: allow` rule still stops at its limit.

Only **allowed** calls count against a budget. A denied call never reached the
upstream, so charging for it would let a misbehaving agent exhaust its own
budget on calls that cost nothing.

## What does a matcher mean when the path resolves to several values?

**The condition holds when at least one value matches — for every matcher,
including the negative ones.**

The tempting alternative is to quantify negative matchers universally, so
`not_prefix` reads as "none of them". Applied to a guardrail, that under-blocks:

```yaml
when:
  "args.items[*].path": { not_prefix: "/srv/app/" }
action: deny
```

Under "any", the batch is denied as soon as one item points outside the
directory. Under "all", a batch of ten paths gets through because one of them
was fine. For a tool whose job is to say no, the first reading is the only
defensible one — and it is also the simpler rule to document.

## Should redaction be a regex over the serialised JSON?

**No. Redact the parsed tree.**

The obvious implementation — run the pattern over `args_json` and replace — has
two failure modes. It produces invalid JSON (`{"api_key": "x"}` with the whole
`"api_key": "x"` replaced is not a document any more), and the patterns people
actually write are `key: value` shaped, which does not match JSON's `"key":
"value"` reliably.

So a pattern is applied twice, to a parsed tree: anchored against a `key: value`
probe per object member (a hit replaces the value), and unanchored against each
string value (a hit replaces only the match). The anchor is what stops
`{"command": "curl -H token=abc"}` from losing its entire command. The details
are in [architecture.md](architecture.md#redaction), and the cases are pinned in
`internal/audit/audit_test.go`.

## Denials: tool result or protocol error?

**A tool result with `isError: true`.** This is the difference between a usable
product and an annoying one. A protocol error looks to the agent like a broken server, and the usual
reaction is to retry the identical call. A tool result carries a sentence the
model can read:

```
agentgate denied: destructive shell command (rule no-destructive-shell)
```

…and the model tries something else. Write your `reason` fields for that reader.

Agentgate's **own** timeout is treated the same way, for the same reason. A
genuine protocol error from an upstream is passed through as a protocol error,
because that is what transparency means.

## Un-routable requests with several upstreams

**Merge the lists; route reads by who listed the item.**

The simple rule would be to route requests with no tool name to the first
upstream. Taken literally, a two-upstream setup could then only ever see the
first server's resources.
Instead `resources/list`, `resources/templates/list` and `prompts/list` are
merged, and `resources/read` and `prompts/get` go to the upstream that listed the
item, falling back to trying each in order. With a single upstream — the common
case — merging and forwarding are indistinguishable.

Only `completion/complete` with an unrecognisable reference still uses the
first-upstream fallback.

## The CLI lives in `internal/cli`, not in `package main`

The conventional layout puts the command tree in `cmd/agentgate/main.go`. It is
in `internal/cli` instead, with `main` reduced to a dozen lines, so that
`internal/gendocs` can build the same command tree the binary runs and generate
the README's command and flag tables from it. `make docs` regenerates them and
CI fails if they drift.

## The kill switch is a file

**A marker file next to the audit database, checked with one `stat()` per call.**

The alternatives were a Unix socket or a signal handler. Both need a running
proxy to talk to, both need to find it, and neither survives a restart. A file
works from a shell, a cron job, a script, the web UI and a honeypot alike; it
freezes every gateway that shares the config at once; and a gateway that comes
up frozen stays frozen, which is the safe direction.

Failing closed matters here: a marker that exists but cannot be parsed still
counts as frozen.

## Honeypots deny outside the rule engine

**A honeypot call never reaches `Evaluate`.** It is handled by its own tool
handler that denies, records with the fixed rule id `honeypot`, notifies and
optionally freezes.

Putting it through the evaluator would let a rule allow it, and there is no
world in which a call to a tool that does not exist should be allowed. It also
keeps the policy evaluator ignorant of the catalogue, which keeps it pure.

## The loop guard counts denied calls too

**The streak is every evaluated call with the same tool and arguments, whatever
the decision.**

The case that decides it: a rule denies a call, and the agent retries it
unchanged, ten times. Counting only allowed calls would never trip the guard
here. Counting every call trips it, and the agent sees a different, escalating
message — "you have made this identical call ten times" — which is more useful
to a model than the tenth copy of the same rule reason.

## Shadow mode records the verdict, not the outcome

**In shadow mode the audit row carries the decision the policy reached
(`deny`, `ask`) with `shadow = 1`, and the call is forwarded.**

The other way round — recording `allow` with a note — would make `stats` and
`replay` blind to what the policy was doing, which is the only reason to run
shadow mode. The `shadow` column is what tells `Blocked()` and the UI that the
verdict was not applied.

The migration that adds the column (`0002_shadow`) is the first schema change
after the initial one, and there is a test that opens a database created by the
first release and upgrades it, so that the path stays exercised.

## Result redaction is opt-in

**`redact_results` is off unless the policy turns it on.**

The transparency promise — bytes in, bytes out when no rule matches — is worth
more than a default that quietly rewrites results. Redaction into the audit log
has no such tension: nobody but the operator reads the log. Redaction into the
model's view of the world is a policy decision, so it lives in `policy:` and it
is documented as the one place agentgate changes a result on purpose.

## Annotations apply the MCP defaults

**A tool with an annotations object but no `destructiveHint` is destructive.**

The MCP specification says the default for `destructiveHint` is `true` and for
`openWorldHint` is `true`. A rule that asks before anything destructive should
therefore ask before a tool whose server bothered to annotate it but did not
say it was safe. A tool with no annotations at all is a different case: the
server said nothing, every `annotations.*` path is missing, and no such rule
matches. Servers lie, so annotations widen an `ask`; they should not be used to
narrow a `deny`.

## Time conditions use local time

**`time.hour` and `time.weekday` are read in the gateway's local time zone.**

"No deploys on Friday afternoon" is a statement about the operator's Friday.
Replay evaluates the recorded timestamp, so a replayed decision matches the
live one; the golden tests pin the zone to UTC so that they do not depend on
where they run.
