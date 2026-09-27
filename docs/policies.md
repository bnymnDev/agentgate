# The policy language

A policy is a default, a mode, some hard stops, an ordered list of rules —
yours, then the packs you switch on — and the labels a session picks up on
its way.

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
4. **Rules**, top to bottom — your own first, then the rules of each
   [pack](#packs) in the order the packs are listed. The first one that
   matches wins.
5. **The default.**

Decisions from steps 1–3 carry the fixed rule ids `frozen`, `loop-guard` and
`budget`, so they can be told apart in the audit log. Three things never reach
the evaluator at all, because they are not a policy question: a call to a
honeypot (rule id `honeypot`), a call that carries a canary out (`canary`), and
a call to a tool pinning has quarantined (`quarantine`). See
[guardrails.md](guardrails.md).

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
| `"args.{command,cmd}"` | whichever of several members exist — see [alternation](#one-of-several-members) |
| `annotations.destructive` | what the server says about the tool; also `read_only`, `idempotent`, `open_world`, `title` |
| `time.hour` | when the call is made, local time, 0–23; also `time.minute` and `time.weekday` (`"monday"`…`"sunday"`) |
| `host.name` | the MCP host that opened the session, as it introduced itself (`claude-code`, `cursor`…); also `host.version` |
| `session.label.<name>` | whether the session carries a [label](#session-labels): `true` or `false`, never missing |
| `session.labels` | every label the session carries |
| `session.called` | every tool the session has already called, in both spellings (`shell__test` and `shell.test`) |
| `session.calls` | how many calls the session has made so far |
| `result.is_error`, `result.text` | what the tool returned — in [label rules](#session-labels) only, since a result exists only once the call has run |

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
| `not_regex` | the value does not match this regular expression | <code>args.sql: { not_regex: '(?i)\bwhere\b' }</code> |
| `prefix` | the value starts with this string | <code>args.path: { prefix: "/etc/" }</code> |
| `not_prefix` | the value does not start with this string | <code>args.path: { not_prefix: "/srv/app/" }</code> |
| `in` | the value is one of these | <code>args.env: { in: ["prod", "staging"] }</code> |
| `gt`, `lt` | the value is a number above / below this; both may be combined | <code>args.amount: { gt: 10, lt: 100 }</code> |
| `exists` | the path is present (`true`) or absent (`false`) | <code>args.dryRun: { exists: false }</code> |
| `includes` | one of the values — or one item of a list among them — is exactly this | <code>session.labels: { includes: private-data }</code> |
| `excludes` | no value, and no item of a list among them, is this; also holds when there is none | <code>session.called: { excludes: shell.test }</code> |
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

The same reading makes a wildcard dangerous in an **allow** rule: one item
inside the directory would let the whole batch through. Fence values in with
deny rules and the `not_*` matchers; `agentgate policy lint` points out an
allow rule that relies on a wildcard.

### Two conditions on one path

A mapping cannot hold the same key twice, so `when` also takes a list of
mappings. All of them still have to hold:

```yaml
- id: absolute-path-outside-the-repo
  tool: "fs.write_file"
  when:
    - args.path: { prefix: "/" }
    - args.path: { not_prefix: "/home/me/repo/" }
  action: deny
```

### One of several members

Servers do not agree on what to call things: the command is `command` in one
shell server and `cmd` in the next. Braces list the alternatives, and the
condition holds when any of the members that exist matches:

```yaml
when:
  "args.{command,cmd,script}": { regex: '\bcurl\b.*\|\s*sh\b' }
```

Subscripts may follow the braces: `"args.{argv,args}[0]"`.

### Lists: `includes` and `excludes`

Every other matcher asks whether *some* value matches. For a question about a
whole list that is the wrong question: `session.called: { not_equals:
shell.test }` holds as soon as the session has called anything else. `includes`
and `excludes` look at all the values at once, open up any list among them, and
ask whether one item is there:

```yaml
- id: tests-before-deploy
  tool: "shell.deploy"
  when:
    session.called: { excludes: shell.test }    # also true when nothing was called
  action: ask
  reason: "deploy without having run the tests in this session"
```

`excludes` is the one matcher besides `exists: false` that holds on a missing
path: a session that has called nothing has not called the tests either.

## Session labels

A label is a fact a session picks up on its way: *this session has read a web
page*, *this session has touched production*. Label rules attach them; rules
ask about them.

```yaml
policy:
  labels:
    - label: touched-prod
      tool: "shell.*"
      when:
        args.command: { regex: '\bprod\b' }
    - label: tests-passed
      tool: "shell.test"
      when:
        result.is_error: false              # label rules may look at the result
  rules:
    - id: deploy-only-after-green-tests
      tool: "shell.deploy"
      when:
        session.label.tests-passed: false
      action: deny
      reason: "run the tests, and make them pass, before deploying"
```

A label rule matches like a rule — a tool pattern and conditions — but has no
action. It is applied **after** a call has gone through, so a label describes
what the session *did*, never what it only tried; that is also why a label rule
may use `result.is_error` and `result.text` and a rule may not. Labels are per
session, never shared between sessions, and the audit log records which call
earned which one.

agentgate attaches two labels itself, and they can be used like any other:

| Label | When |
|---|---|
| `injection-suspected` | a tool result carried text hidden in invisible characters, or instructions addressed to the model |
| `canary-read` | a tool result contained a [canary](guardrails.md#canaries) |

Label names are lower-case letters, digits, `-` and `_`. A condition on a label
no rule attaches never changes, and `agentgate policy lint` says so.

## Packs

A pack is a named, reviewed set of rules and label rules. Switch one on by name:

```yaml
policy:
  packs:
    - baseline
    - secrets
    - lethal-trifecta
    - name: filesystem
      with: { workspace: /home/me/repo }
```

or from the command line, which edits only the lines of the list:

```sh
agentgate policy packs                                     # what ships
agentgate policy pack lethal-trifecta                      # read one in full
agentgate policy add filesystem --with workspace=~/code/app
agentgate policy remove business-hours
```

**Your rules come first.** Pack rules are evaluated after your own rules, so a
pack can be switched on wholesale and still be overruled for one tool:

```yaml
policy:
  packs: [baseline]
  rules:
    - id: our-ci-may-reset
      tool: "shell.exec"
      when:
        host.name: { equals: "ci-bot" }
        args.command: { regex: '^git reset --hard' }
      action: allow
```

A pack rule's id carries the pack's name — `baseline/rm-rf-root` — in the
decision, the audit log and the stats. Label names are left alone, because
labels are a vocabulary packs and your own rules share.

**Parameters** are filled in on the parsed YAML, value by value, so a value can
never change a pack's structure; a value that is a whole placeholder takes the
type of what is put in (`lt: "{{last_hour}}"` becomes the number 17). A
parameter marked as a path is expanded (`~`, `${ENV}`) and cleaned.

**Your own packs** are files, named relative to the config:

```yaml
policy:
  packs:
    - ./packs/team.yaml
```

```yaml
# packs/team.yaml
name: team
description: What the team agreed on.
params:
  branch:
    description: the protected branch
    default: main
rules:
  - id: no-push
    tool: "*"
    when:
      args.branch: { equals: "{{branch}}" }
    action: deny
    reason: "{{branch}} is protected"
```

The packs that ship with agentgate:

<!-- BEGIN:packs -->
| Pack | Parameters | What it does |
|---|---|---|
| `ask-destructive` | — | Asks before any tool the server itself describes as destructive. Relies on the MCP tool annotations, so it covers exactly as much as the servers are honest about; tools without annotations are left to other rules. |
| `baseline` | — | The commands no agent should run unsupervised: recursive deletes of roots and home directories, disk wipes, force-pushes to main, and SQL that drops or empties tables. It looks at the arguments shell, git and database tools actually take, so it works whatever the servers are called. |
| `business-hours` | `first_hour`, `last_hour` | Outside working hours and at weekends, anything that changes something waits for a human who is awake to see it. Hours are the gateway's local time. |
| `database` | — | Every write to a database waits for a human: INSERT, UPDATE, DELETE, MERGE, COPY FROM, and schema changes. SELECTs go through. Pair it with baseline, which denies the statements that destroy a table outright. |
| `filesystem` | `workspace` (required) | Writes are confined to one directory. Any tool whose name says it writes, edits, moves, creates or deletes, and whose path argument is absolute and outside the workspace, is denied; so is a relative path that climbs out with "..". Paths are expected to be absolute, as the reference filesystem server uses them. |
| `git-safety` | — | Git beyond baseline: pushes to main, pushed tags, deleted branches, history rewrites and global git configuration all wait for a human. |
| `github` | — | For GitHub, GitLab and Gitea servers, by tool name: deleting a repository is denied; merging, writing to the default branch, changing settings and anything other people will see — issues, comments, pull requests, releases — waits for a human. Reads are left alone. |
| `lethal-trifecta` | — | An agent that has read untrusted content, can reach private data and can send things out can be talked into leaking that data. This pack labels sessions that fetch web pages, issues or mail as untrusted-input, and from then on asks a human before the session sends anything anywhere. A session whose tool results carried hidden text or instructions aimed at the model (the injection-suspected label agentgate attaches itself) sends nothing at all. |
| `read-only` | — | The agent may look but not touch. Tools the server marks read-only, and tools whose names say they only read — get, list, read, search and so on — are allowed; SQL that writes is denied even through a read-sounding tool; everything else is denied. Your own rules still come first, so you can carve out exceptions. |
| `secrets` | — | Keeps key material out of reach — SSH and GPG keys, cloud and registry credentials, .netrc and friends — and labels sessions that read .env files with private-data, so that other rules (and the lethal-trifecta pack) can treat them with more care. |
| `shell-strict` | — | A stricter shell on top of baseline: reverse shells, decode-and-run tricks and shutting the machine down are denied; sudo, system package installs and persistence in shell profiles, cron and services wait for a human. |
<!-- END:packs -->

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
before the agent reads them, and `strip_invisible: true` removes the characters
that render as nothing — the way a web page hides instructions from the person
reading it. They are the only two places agentgate deliberately changes a
result, and both are off by default. See
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
agentgate check --tool 'mail.send' --label untrusted-input --label private-data
agentgate check --tool 'shell.deploy' --called shell.test --host ci-bot
agentgate check --tool 'x' --annotations destructive=true              # test an annotation rule
agentgate policy lint agentgate.yaml           # rules that never fire, allows that let too much through
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
