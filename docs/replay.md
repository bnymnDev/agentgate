# Replay and diff

The audit log is not just a record. It is a corpus of real calls you can run a
new policy against before you trust it.

## Dry run: what would this policy have done?

```sh
agentgate replay 01JD8K2M --dry-run
```

Every recorded call in the session is re-evaluated against the policy as it
stands **now**, and the differences are printed. Nothing is sent anywhere; no
upstream is even contacted.

```
replaying session 01JD8K2MQ9Y0RG4T2VN6HB1XZ7 (14 calls) — dry run, nothing is sent

 #  TOOL                 WAS    NOW    CHANGE
 ─  ────                 ───    ───    ──────
 0  fs__read_file        allow  allow
 1  fs__write_file       allow  deny   allow → deny
 2  shell__exec          allow  allow
 …

12 allowed, 2 not allowed, 1 decisions changed

changed decisions:
  fs__write_file                   allow → deny  writes are confined to the repository
```

This works because policy evaluation is pure: the recorded arguments plus the
current policy are all the evaluator needs. The arguments are decoded exactly
the way the live proxy decodes them, numbers included, so a replayed decision is
the decision the proxy would have made.

**Budgets are simulated as the walk proceeds.** If you add
`calls_per_session: 10` and replay a session with 14 calls, the report shows the
last four flipping to `deny` at exactly the point the session would have run
out.

Use it to answer:

- *Would this new rule have caught the thing that went wrong?*
- *How much of yesterday's normal work would this rule have broken?*
- *Is my `deny`-by-default policy complete enough to switch on?*

## Live replay: does it still do the same thing?

```sh
agentgate replay 01JD8K2M
```

Without `--dry-run`, calls that the current policy allows are actually re-sent
to the upstreams that are configured now. The fresh result is hashed with the
same canonical-JSON hash the audit log used, so the report can say whether the
answer changed.

```
 #  TOOL                 WAS    NOW    CHANGE  RESULT
 0  fs__read_file        allow  allow          same
 1  github__get_issue    allow  allow          differs
```

`--only-allowed` skips calls that were denied when they were recorded, which is
usually what you want: those calls never reached the server in the first place.

> Replay re-sends real calls to real servers. On anything that writes, use
> `--dry-run`, or point the config at a staging upstream first.

A replay records nothing itself. It reports.

Results that were truncated on the way into the database (see
`audit.max_result_bytes`) are marked rather than compared: the stored hash is of
the whole result, but the stored body is not, and pretending otherwise would
produce a confident wrong answer.

## Diff: what is different between these two sessions?

```sh
agentgate diff 01JD8K2M 01JD9P4X
```

```
a  01JD8K2MQ9Y0RG4T2VN6HB1XZ7
b  01JD9P4XR1Z8TH5V3WQ7JC2YB9

   TOOL                 STATUS    A              B
~  fs__write_file       args      allow 4f3a2b1c  allow 9d8e7f6a
+  shell__exec          only-b    -              allow 1a2b3c4d
~  github__get_issue    result    allow 5e6f7a8b  allow c4d3e2f1

11 same, 1 different arguments, 1 different results, 0 different decisions, 0 only in a, 1 only in b
```

The two call lists are aligned with a longest-common-subsequence over the tool
names, so an inserted or removed call shows up as one row instead of pushing
everything after it out of step. For calls that line up, the comparison is on
hashes:

| Status | Meaning |
|---|---|
| `same` | same tool, same arguments, same result |
| `args` | same tool, different arguments |
| `result` | same tool and arguments, different result |
| `decision` | allowed in one session, not in the other |
| `only-a` / `only-b` | the call happened in one session and not the other |

Identical calls are hidden unless you pass `--all`. `diff` exits non-zero when
the sessions differ, which makes it usable as an assertion:

```sh
agentgate diff "$BASELINE" "$LATEST" || echo "the agent did something new"
```

Both commands take `--json` for anything you want to script.

## Stats: what did it actually do?

```sh
agentgate stats --since 24h
agentgate stats --session 01JD8K2M
agentgate stats --since 7d --markdown     # paste into a PR or a post
```

```
agentgate stats — last 24h

  sessions 6      calls 412    denied 9      shadowed 0      honeypot trips 1    errors 2    tokens ~148k

TOOL                CALLS  ALLOWED  DENIED  ERRORS  AVG MS  TOKENS  LAST SEEN
────                ─────  ───────  ──────  ──────  ──────  ──────  ─────────
fs__read_file       201    201      0       0       4       92k     09-04 14:31
shell__exec         88     81       7       2       213     31k     09-04 14:30
fs__write_file      54     52       2       0       6       18k     09-04 14:29
db__drop_all_tables 1      0        1       0       0       0       09-04 11:02

RULE                    DECISION  TIMES
no-destructive-shell    deny      7
stay-in-the-repo        deny      2
honeypot                deny      1
```

## Suggest: write the allow-list for me

```sh
agentgate policy suggest --since 7d
agentgate policy suggest --session 01JD8K2M --out policy.yaml
```

Reads the same window and prints a complete `policy:` section: `default:
deny`, one `allow` rule per tool the agent actually used (with the observed
call count as its reason), a session budget a little above the busiest session
seen, and a loop guard. Tools that were only ever denied get a comment, not a
rule. Honeypot trips are called out.

It is a starting point, not a verdict — read it, tighten it, then
`agentgate policy validate` it.

## A workflow that works

1. Run with `default: allow` and no rules for a day. You now have a corpus.
   (Or run the strict policy you have in mind with `mode: shadow`, which
   records what it would have done and blocks nothing.)
2. Look at what actually happened: `agentgate stats --since 24h`, then
   `agentgate ui`.
3. `agentgate policy suggest > policy.yaml` for a deny-by-default draft, or
   write the rules you wish had been there.
4. `agentgate replay <yesterday> --dry-run` for each interesting session.
5. Tighten until the only things that flip to `deny` are the ones you meant.
6. Remove `mode: shadow`, or switch `default` to `deny`, when the allow-list
   is complete enough.
