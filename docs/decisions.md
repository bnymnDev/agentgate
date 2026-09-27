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

**A tool with an annotations object but no `destructiveHint` is destructive —
unless it is read-only.**

The MCP specification says the default for `destructiveHint` is `true` and for
`openWorldHint` is `true`, and that `destructiveHint` only means something for
a tool that is not read-only; a read-only tool is therefore never destructive,
whatever else it says. A rule that asks before anything destructive should
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

## Labels are applied after the call, not before

**A label rule matches a call that has gone through, with its result.**

Labelling on the way in would label a session for a call the policy denied,
so a session that only *tried* to read a secret would be treated as one that
had. Labelling on the way out means a label is a fact about what the session
did, and it is what lets a label rule look at the result — "the tests passed",
"the page had hidden text in it". The cost is that a label cannot influence
the decision on the call that earns it; that is the right order anyway.

## `excludes` instead of changing what `not_equals` means

**Negative matchers keep "some value matches"; `includes` and `excludes` are
new matchers that look at every value at once.**

"Has the session run the tests?" is a question about a whole list, and
`not_equals` answers a different one: it holds as soon as *any* value is not
equal, which on `session.called` is as soon as the session has called
anything else. Changing `not_equals` to mean "no value equals" would have
fixed that and broken the reason it works the way it does — `not_prefix` on
a wildcard path denies a batch as soon as one item is outside the directory.
Two new matchers say what they mean and leave the old ones alone.

## Your own rules come before the packs

**Pack rules are appended after the rules in the config.**

A pack is switched on wholesale, and every team has the one exception — the
CI job that may reset a branch, the scratch directory that may be wiped. With
your rules first, the exception is one rule above the pack; with the pack
first, it would mean editing the pack. Pack rule ids carry the pack's name, so
the audit log still says which of the two decided.

## Pack parameters are substituted into the parsed YAML

**A `{{param}}` is replaced value by value on the YAML node tree, never in the
text.**

Text substitution would let a parameter value — a path with a quote and a
newline in it — add a rule to the pack, or remove one. Filling in scalar
values after parsing makes that impossible, and a value that is a whole
placeholder can take the type of what is put in, so `lt: "{{last_hour}}"`
becomes a number.

## Pinning warns by default

**`pinning.mode` defaults to `warn`: tools are pinned and changes reported,
and nothing is held back.**

Holding back a changed tool is the stronger defence, and it changes what the
host sees — which breaks the transparency promise for a user who never asked
for it, and would do so the first time a server ships an ordinary update.
`warn` costs nothing and records the change in the lockfile; `enforce` is one
line away, and `agentgate init` points at it.

## Canaries, honeypots and quarantine are not rules

**All three stop a call before or instead of `Evaluate`, and all three hold in
shadow mode.**

They are tripwires. A rule is something you tune; there is no tuning that
should let a planted credential leave, a call to a tool that does not exist go
through, or a tool whose definition changed under you reach the model. Keeping
them out of the evaluator also keeps it pure: it knows nothing of the catalog,
the lockfile or the canary store. The kill switch holds in shadow mode for the
same reason — shadow mode tries out a policy, and the kill switch is not part
of one.

## The audit log is a hash chain, and retention cuts only its front

**Every call links to the one before it; pruning removes a prefix and leaves
an anchor.**

The audit log is the evidence of what an agent did, and evidence that can be
edited without trace is not evidence. A chain makes every edit, deletion and
insertion show. Pruning by session, as before, would have punched holes into
the middle of the chain wherever a long session overlapped short ones, so
retention now removes calls from the front, stops at the first call still
within the period, and keeps the last removed link as the anchor. What a chain
cannot show — its end being cut off — is what `verify --anchor` is for.

## A stateless discover opens no session

**On MCP protocol 2026-07-28 the audit session is opened by the first call,
not by `server/discover`.**

Discovery is stateless. Over Streamable HTTP it runs on a throwaway session of
its own, and the calls that follow arrive on another; opening a session on the
discover recorded every HTTP host twice, once as an empty session that never
ended. The first call carries the host's identity in its `_meta` anyway.

## Strip invisible characters only when asked

**`strip_invisible` is off by default, and the scan that labels a session
`injection-suspected` is always on.**

Detection changes nothing the agent sees, so it can run everywhere; the label
is what lets a policy act on it. Removing characters from a result changes the
result, which is a policy decision like result redaction — and the audit log
keeps the result as it came either way, because that is the evidence.
