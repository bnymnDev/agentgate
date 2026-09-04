# Guardrails

The policy language says which calls get through. The guardrails in this
document are the things around it: the ways a gateway stops an agent that the
rules did not anticipate, and the ways you find out.

## The kill switch

```sh
agentgate freeze "something is off"
agentgate unfreeze
```

While the gateway is frozen every `tools/call`, in every session, on every
agentgate that shares the config, is denied with

```
agentgate denied: agentgate is frozen; run `agentgate unfreeze` to let calls through again (rule frozen)
```

Nothing is restarted and no connection is dropped. The agents stay connected
and keep getting readable denials, which is exactly what you want while you
work out what happened.

**It is a file.** The switch is a marker file next to the audit database
(`~/.agentgate/FROZEN` by default; `agentgate status` prints the path). That
design has consequences worth knowing:

- It works with no proxy running, from any shell, from a cron job, from a
  script that noticed something in a log.
- It survives a restart. A gateway that starts frozen says so on its first log
  line and stays that way until someone unfreezes it.
- It is one `stat()` per call — no socket, no signal, no IPC.
- The web UI has a button for it on every page.
- A honeypot can throw it (below).

Freezing is idempotent: the first reason wins, because the first reason is the
interesting one. The marker records who threw the switch and when.

## Honeypot tools

```yaml
honeypots:
  action: freeze          # or deny
  tools:
    - name: db__drop_all_tables
      description: "Drop every table in the production database. Irreversible."
    - name: fs__delete_everything
      description: "Recursively delete the whole workspace. Cannot be undone."
```

A honeypot is advertised to the host exactly like a real tool: it shows up in
`tools/list` with its description and an open schema. There is nothing behind
it. A call to it is denied, recorded with the rule id `honeypot`, sent to every
webhook that subscribed to `honeypot`, and, with `action: freeze`, throws the
kill switch.

Why this works: an agent has no reason to call a tool its operator never asked
it to use. If it does, one of three things has happened —

1. **prompt injection** — a file, a web page, a tool result told it to;
2. **a hallucinated capability** — it invented a reason;
3. **the model is being creative** in a way that should not reach production.

All three are things you want to know about *immediately*, and none of them
can be caught by a rule on a real tool, because a real tool has legitimate
uses. The decoy has none.

Make them convincing. A honeypot named `test_tool_do_not_use` catches nothing.
`db__drop_all_tables` with a description that sounds like the rest of the
server's tools is bait an injected instruction will happily take. Give it the
prefix of a real upstream so it sits among that server's tools. A honeypot
whose name collides with a real tool is skipped and logged; the real tool wins.

`agentgate stats` counts honeypot trips separately, `agentgate tail` marks them
as TRAP, and the web UI highlights them.

## Loop guard

```yaml
policy:
  loop_guard:
    repeats: 10
```

The identical call — same tool, same arguments byte for byte — made ten times
in a row is denied with

```
loop guard: the identical call has been made 10 times in a row; change the arguments or stop (rule loop-guard)
```

This is the runaway-agent stop. A model that keeps calling `read_file` on the
same path, or retrying a command that keeps failing the same way, is not going
to get a different answer on the eleventh try; it is going to keep going until
something external stops it. This is the something.

The streak counts every evaluated call, allowed or denied, and resets the
moment a different call comes in. So a call that was denied by a rule and
retried unchanged ten times gets the loop-guard reason instead — which is
a stronger signal to the model than the same rule reason for the tenth time.

`repeats: 0` (the default) turns the guard off. Legitimate polling with
identical arguments would trip a low setting; ten is a sane starting point,
and `agentgate policy suggest` includes it.

## Rate limit and token budget

```yaml
policy:
  budget:
    calls_per_minute: 60
    tokens_per_session: 200000
```

`calls_per_minute` is a sliding window over the trailing sixty seconds of
allowed calls. `tokens_per_session` is agentgate's estimate of characters ÷ 4
across arguments and results — rough, but a session that has pushed two
hundred thousand tokens through its tools is a session worth looking at.
Both are hard stops checked before the rules, like every budget.

## Shadow mode

```yaml
policy:
  mode: shadow
```

In shadow mode the policy is evaluated and every decision is recorded exactly
as it would have been — and then the call is forwarded regardless. The audit
log, `agentgate tail` and the web UI show these calls as `shadow · would deny`.
Webhooks can subscribe to the `shadow` event.

Use it to try a policy against live traffic without the cost of being wrong:

1. write the strict policy you think you want;
2. set `mode: shadow` and run for a day;
3. `agentgate stats --since 24h` shows what would have been blocked;
4. tune until the shadowed denials are the ones you meant;
5. delete the `mode` line.

`agentgate check` reports shadow mode too, so a scripted check does not fail on
a policy that would not actually block.

## Result redaction

```yaml
policy:
  redact_results: true
```

Redaction always applies to what goes into the audit log. With
`redact_results` it also applies to what the *agent* gets back: text content,
embedded text resources and structured results are scrubbed with the same
patterns before the response leaves agentgate. The filesystem tool reads
`.env`; the model receives

```
DATABASE_URL=[REDACTED]
STRIPE_KEY=[REDACTED]
```

This is the one place agentgate deliberately changes a tool result, which is
why it is off by default and why turning it on is a policy decision. The
built-in patterns cover API keys, bearer tokens, cloud credentials, private
key headers, JWTs and the usual `password=` shapes; add your own under
`audit.redact`.

## Notifications

```yaml
notify:
  webhooks:
    - url: https://ntfy.sh/my-agent
      format: ntfy
    - url: https://hooks.slack.com/services/T000/B000/XXXX
      format: slack
      events: [honeypot, freeze]
    - url: https://ops.example.com/agentgate
      format: json
      headers: { Authorization: "Bearer ${OPS_TOKEN}" }
```

| Event | When |
|---|---|
| `deny` | a call was denied and the agent was told so |
| `ask` | a call is waiting for a human |
| `honeypot` | a decoy was called |
| `freeze` | the kill switch was thrown by the proxy (a honeypot, the web UI) |
| `error` | a forwarded call failed or timed out |
| `shadow` | shadow mode would have denied or asked |

The default subscription is `deny, ask, honeypot, freeze`. `format: json`
posts agentgate's own event object; `slack`, `discord` and `ntfy` post the
message shape those services render directly, so a webhook URL from any of
them works with no glue. ntfy deliveries carry a title, a tag and, for
honeypot and freeze events, urgent priority — the one you want to buzz.

Delivery is asynchronous with a ten-second deadline and never touches the
request path. Arguments are redacted before they are sent.

## Seeing what happened

```sh
agentgate status                  # frozen? policy summary, last 24h in one line
agentgate tail                    # live, coloured, from any terminal
agentgate stats --since 7d        # per tool, per rule; --markdown to paste
agentgate ui                      # the same in a browser
```

`tail` reads the audit database rather than the proxy's stdout, so it works
against a gateway that an editor launched as a subprocess — the one whose
output you can never see otherwise.
