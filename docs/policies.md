# The policy language

A policy is a default, a mode, some hard stops, and an ordered list of rules.

```yaml
policy:
  default: allow            # allow | deny
  mode: enforce             # enforce | shadow
  redact_results: false     # true: secrets are scrubbed before the agent sees them
  budget:
    calls_per_session: 500
    calls_per_minute: 60
    tokens_per_session: 200000
    calls_per_tool:
      fs.write_file: 50
  loop_guard:
    repeats: 10
  rules:
    - id: no-destructive-shell
      tool: "shell.*"
      when:
        args.command: { regex: '\brm\s+-rf' }
      action: deny
      reason: "destructive shell command"
```

Evaluation happens in this order, and stops at the first thing that decides:

1. **The kill switch.** A frozen gateway denies everything (`agentgate freeze`).
2. **The loop guard.** The identical call repeated too often is denied.
3. **Budgets.** A budget is a hard cap; no rule can lift one.
4. **Rules**, top to bottom. The first one that matches wins.
5. **The default.**

Decisions from steps 1–3 carry the fixed rule ids `frozen`, `loop-guard` and
`budget`, so they can be told apart in the audit log. Honeypot trips (rule id
`honeypot`) never reach the evaluator at all; see [guardrails.md](guardrails.md).

`mode: shadow` changes what is *done* with a decision, not the decision: it is
recorded as reached, and the call is forwarded anyway.

Evaluation is pure. The same policy and the same call always produce the same
decision — no clock, no filesystem, no network — which is what makes
[replay](replay.md) trustworthy.

## Rules

| Field | Required | What it does |
|---|---|---|
| `id` | yes | Identifies the rule in decisions, logs and the audit trail. Must be unique. |
| `tool` | one of | Which tools the rule covers. |
| `when` | `tool`/`when` | Conditions on the call's arguments. All of them must hold. |
| `action` | yes | `allow`, `deny` or `ask`. |
| `reason` | no | Shown to the agent and stored in the audit log. Write one; the agent reads it. |

A rule with neither `tool` nor `when` is rejected, because it would silently
match everything. If that is what you want, say `tool: "*"`.

## Matching tool names

`tool` accepts three spellings:

| Spelling | Meaning |
|---|---|
| `fs__write_file` | exact name |
| `fs.*` | glob — `*` is any run of characters, `?` is one |
| `github.get_*\|github.list_*` | alternation — split on `\|`, each side a glob |
| `/^fs__(read\|write)_file$/` | a Go regular expression, delimited by slashes |

Globs are anchored: the whole name has to match. Every character other than `*`
and `?` is literal, so the dot in `fs.write_file` matches a dot and nothing else.

**Separator tolerance.** A pattern is tested against both the name the host sees
(`fs__write_file`) and the canonical `upstream.tool` spelling (`fs.write_file`),
so a policy keeps working if `prefix_separator` changes, and the examples in this
file work whichever separator you use.

## Conditions

`when` is a mapping of a path to a matcher. Every entry has to hold (AND); write
two rules if you want OR.

```yaml
when:
  args.env: { equals: "prod" }
  args.force: { equals: true }
```

### Paths

| Path | Points at |
|---|---|
| `args` | the whole arguments object |
| `args.path` | an object member |
| `args.target.host` | a nested member |
| `"args.items[0]"` | an array element (negative indices count from the end) |
| `"args.items[*].sku"` | a member of **every** array element |
| `tool` | the exposed tool name, `fs__write_file` |
| `tool_name` | the name the upstream uses, `write_file` |
| `upstream` | the upstream name, `fs` |
| `annotations.destructive` | what the server says about the tool; also `read_only`, `idempotent`, `open_world`, `title` |
| `time.hour` | when the call is made, local time, 0–23; also `time.minute` and `time.weekday` (`"monday"`…`"sunday"`) |

Anything else is a validation error, so a typo in a path fails
`policy validate` rather than quietly never matching.

**Annotations** are the MCP tool annotations the upstream server attached.
They are the server's claims about itself — exactly as trustworthy as the
server — so use them to widen an `ask`, not to narrow a `deny`:

```yaml
- id: ask-before-anything-destructive
  tool: "*"
  when: { annotations.destructive: true }
  action: ask
```

Per the MCP specification a tool that has annotations but does not mention
`destructiveHint` counts as destructive, and one that does not mention
`openWorldHint` as open-world. A tool with no annotations at all says nothing:
every `annotations.*` path on it is missing.

**Time** conditions read the call's timestamp in the gateway's local time zone.
Replay evaluates the recorded timestamp, so "no deploys on Friday afternoon"
replays the way it ran:

```yaml
- id: no-deploys-on-friday-afternoon
  tool: "*deploy*"
  when:
    time.weekday: { equals: "friday" }
    time.hour: { gt: 15 }
  action: deny
```

`agentgate check --at "friday 17:00"` tests such a rule without waiting for
Friday.

> Quote paths that contain `[` or `*` when you use YAML's inline mapping form:
> `{ "args.items[*].sku": { prefix: "BAD-" } }`. Unquoted, YAML reads `*` as an
> alias.

### Matchers

<!-- BEGIN:matchers -->
| Matcher | Holds when | Example |
|---|---|---|
| `equals` | the value is exactly this | <code>args.dryRun: { equals: false }</code> |
| `not_equals` | the value is anything but this | <code>args.mode: { not_equals: "dry" }</code> |
| `regex` | the value matches this Go regular expression | <code>args.command: { regex: '\brm\s+-rf' }</code> |
| `prefix` | the value starts with this string | <code>args.path: { prefix: "/etc/" }</code> |
| `not_prefix` | the value does not start with this string | <code>args.path: { not_prefix: "/srv/app/" }</code> |
| `in` | the value is one of these | <code>args.env: { in: ["prod", "staging"] }</code> |
| `gt`, `lt` | the value is a number above / below this; both may be combined | <code>args.amount: { gt: 10, lt: 100 }</code> |
| `exists` | the path is present (`true`) or absent (`false`) | <code>args.dryRun: { exists: false }</code> |
<!-- END:matchers -->

Two shorthands save a level of nesting:

```yaml
args.mode: "live"              # same as { equals: "live" }
args.env: ["prod", "staging"]  # same as { in: ["prod", "staging"] }
```

Exactly one matcher per condition, except `gt` and `lt`, which may be combined
into a range.

### What a matcher compares

- **Numbers** compare by value: `0`, `0.0` and `"0"`-free JSON numbers are the
  same number. `gt`/`lt` on a non-number never match.
- **Strings** compare exactly. `regex` and the prefix matchers use the string
  form of the value: scalars keep their natural spelling, and objects and arrays
  are rendered as JSON, so you can point a regex at a whole subtree.
- **Objects and arrays** compare by their canonical JSON, so `equals` works on
  nested structures.

### A missing path

If a path resolves to nothing, the condition is **false** — including for the
negative matchers. `args.path: { not_prefix: "/srv/" }` does not fire when there
is no `args.path` at all, because there is nothing to make a claim about.

To match on absence, say so:

```yaml
when:
  args.dryRun: { exists: false }
```

### Array wildcards

A path with `[*]` resolves to several values, and the condition holds when **at
least one** of them matches. That is the safe reading for a guardrail:

```yaml
- id: no-writes-outside-the-app
  tool: "fs.write_many"
  when:
    "args.items[*].path": { not_prefix: "/srv/app/" }
  action: deny
```

denies the batch as soon as a single item points outside the directory.
Requiring every item to match would let the batch through because one entry in
it happened to be fine.

## Budgets

```yaml
budget:
  calls_per_session: 500
  calls_per_minute: 60
  tokens_per_session: 200000
  calls_per_tool:
    fs.write_file: 50
    shell.exec: 20
```

| Budget | Counts |
|---|---|
| `calls_per_session` | allowed calls in the session |
| `calls_per_tool` | allowed calls per exposed tool; keys get the same separator tolerance as rule patterns |
| `calls_per_minute` | allowed calls in the trailing sixty seconds — a sliding window |
| `tokens_per_session` | estimated tokens (characters ÷ 4 of arguments plus results) through tools so far |

All are per downstream session, and only **allowed** calls count: a denied call
did not cost anything upstream, so it does not spend budget. Zero or absent
means unlimited.

A call over budget is denied with a reason of the form
`budget: limit of 50 calls for fs.write_file reached` and the rule id `budget`.

## Loop guard

```yaml
loop_guard:
  repeats: 10
```

The identical call — same tool, same arguments — made `repeats` times in a row
is denied on the next attempt with the rule id `loop-guard`. Unlike budgets,
the streak counts denied calls too, so an agent retrying a denied call
unchanged gets an escalating message rather than the same one forever. A
different call resets the streak. Zero disables the guard.

## Mode and result redaction

`mode: shadow` evaluates everything and blocks nothing: decisions are recorded
as reached, flagged as shadow, and the call is forwarded. It is how a policy is
tried against live traffic before it is trusted. See
[guardrails.md](guardrails.md#shadow-mode).

`redact_results: true` applies the audit redaction patterns to tool results
before the agent reads them. It is the one place agentgate deliberately changes
a result, and it is off by default. See
[guardrails.md](guardrails.md#result-redaction).

## `ask`

`action: ask` parks the call until a human decides. What that means in practice
depends on `approval.mode` and on whether the web UI is running — see
[config.md](config.md#approval). If nobody can be asked, the call is denied with
a reason that says exactly that, never silently allowed. A human can allow one
call or the tool for the rest of the session; either way the rule that asked is
what the audit log records.

`default: ask` is rejected: a default has to be a decision.

## Testing a policy

```sh
agentgate policy validate agentgate.yaml       # every problem, in one pass
agentgate check --tool 'fs.write_file' --args '{"path":"/etc/passwd"}'
agentgate check --tool 'fs.write_file' --args '{}' --calls-so-far 60   # test a budget
agentgate check --tool 'shell.exec' --args '{}' --repeats 10           # test the loop guard
agentgate check --tool 'deploy' --at 'friday 17:00'                    # test a time rule
agentgate replay <session> --dry-run           # against a real recorded session
```

`check` exits non-zero when the call would be denied, so it works as a test in
CI:

```sh
agentgate check --tool 'shell.exec' --args '{"command":"rm -rf /"}' && echo "THIS SHOULD NOT HAPPEN"
```

The policy engine's own test suite is a set of golden files:
`testdata/policies/*.yaml` plus `testdata/calls/*.json` produce
`testdata/golden/*.golden`, one line per call. `make golden` regenerates them —
the diff is the policy language's changelog, and a surprising line in it is a
bug.
