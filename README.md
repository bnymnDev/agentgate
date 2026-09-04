<h1 align="center">agentgate</h1>

<p align="center"><strong>Firewall, kill switch and flight recorder for your AI agent's tools.</strong></p>

<p align="center">
One binary between your MCP host and your MCP servers.<br>
Every tool call is checked against a policy, recorded, replayable — and stoppable with one command.
</p>

```
  MCP host                 agentgate                    MCP servers
┌────────────┐   stdio   ┌──────────────────┐  stdio  ┌──────────────┐
│  your      │──────────▶│ policy   audit   │────────▶│ filesystem   │
│  agent     │◀──────────│ ├ allow  ├ sqlite│◀────────│ github       │
└────────────┘           │ ├ deny   ├ replay│  http   │ shell, db, … │
                         │ ├ ask    └ tail  │────────▶└──────────────┘
                         │ └ freeze         │
                         └──────────────────┘
```

No changes to the host. No changes to the servers. No cgo, no runtime, no cloud.

---

## Seven things it does that nothing else does

| | |
|---|---|
| **Kill switch** | `agentgate freeze` denies every tool call from every agent on the machine, instantly, without dropping a connection. `agentgate unfreeze` when you have looked. |
| **Honeypot tools** | Advertise a tool that does not exist — `db__drop_all_tables` — and find out the moment an agent tries to use it. That is a prompt injection, caught red-handed. Optionally freezes everything on the spot. |
| **Loop guard** | The same call with the same arguments ten times in a row is not diligence, it is a stuck agent burning money. agentgate stops it and tells the model why. |
| **Shadow mode** | Run a strict policy without enforcing it. See what it *would* have blocked in the audit log, tune, then flip the switch. |
| **Time-travel policy testing** | `agentgate replay <session> --dry-run` re-runs yesterday's real session against today's policy and shows exactly which decisions change. |
| **Secret redaction, both ways** | Secrets are scrubbed before they reach the audit log — and, if you say so, before they reach the model. Your agent reads `.env`, the model gets `[REDACTED]`. |
| **Slack, Discord, ntfy, anything** | A denial, an approval request, a honeypot trip: get it on your phone. A webhook URL is all it takes. |

Plus the boring parts done properly: a YAML policy language with globs, regexes and JSONPath-lite argument matching; budgets per session, per tool, per minute and per token; rules on what the *server itself* says about a tool (`annotations.destructive: true`); rules on the time of day (no deploys on Friday afternoon); approvals from the terminal or a web UI; a local SQLite audit log with replay, diff, stats and a live `tail`; and a `policy suggest` that writes a deny-by-default policy from what your agent actually did.

---

## 60 seconds

```sh
go install github.com/bnymnDev/agentgate/cmd/agentgate@latest
```

or with Homebrew:

```sh
brew tap bnymnDev/agentgate https://github.com/bnymnDev/agentgate
brew install --cask agentgate
```

Prebuilt binaries for linux, macOS and Windows (amd64 and arm64) are on the
[releases page](https://github.com/bnymnDev/agentgate/releases).

**1.** Write `agentgate.yaml`:

```yaml
version: 1

upstreams:
  - name: fs
    stdio: ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/home/me/repo"]

honeypots:
  action: freeze
  tools:
    - name: fs__delete_everything
      description: "Recursively delete the whole workspace. Cannot be undone."

policy:
  default: allow
  loop_guard: { repeats: 10 }
  budget: { calls_per_minute: 60 }
  rules:
    - id: stay-in-the-repo
      tool: "fs.write_file"
      when:
        args.path: { not_prefix: "/home/me/repo/" }
      action: deny
      reason: "writes are confined to the repository"
```

**2.** Wherever your host config launched the server, launch agentgate instead:

```json
{ "command": "agentgate", "args": ["run", "--stdio", "--config", "/home/me/agentgate.yaml"] }
```

Works with any MCP host that starts stdio servers — Claude Code (`.mcp.json`), Claude Desktop (`claude_desktop_config.json`), Cursor (`.cursor/mcp.json`), Zed, Windsurf, your own.

**3.** Watch:

```sh
agentgate tail
```

```
14:02:11  allow   fs__read_file          3ms
14:02:12  allow   fs__write_file         5ms
14:02:14  DENY    fs__write_file         0ms  writes are confined to the repository
14:02:19  TRAP    fs__delete_everything  0ms  honeypot: fs__delete_everything does not exist. Calling it means…
the gateway is now FROZEN
```

That last line is an agent that was told, somewhere in a file it read, to wipe the workspace. It did not get to.

---

## The agent gets a reason, not a broken pipe

A denied call is not a transport error. It is a tool result the model can read:

```
agentgate denied: writes are confined to the repository (rule stay-in-the-repo)
```

…and it adapts. A blocked agent that understands *why* it was blocked stops trying the same thing. One that only sees an error retries until your budget is gone.

---

## Shadow first, enforce later

Nobody writes a correct deny-list on the first try. So don't:

```yaml
policy:
  mode: shadow        # record what would happen, block nothing
```

Run your agent for a day. Then:

```sh
agentgate stats --since 24h        # what did it actually do?
agentgate policy suggest > p.yaml  # an allow-list of exactly that, default: deny
agentgate replay <session> --dry-run   # what would the new policy have changed?
```

When the only things that flip to `deny` are the ones you meant, delete the `mode: shadow` line.

---

## The policy language, in one screen

```yaml
policy:
  default: allow                 # or deny, for a locked-down setup
  mode: enforce                  # or shadow
  redact_results: false          # true: secrets never reach the model
  budget:
    calls_per_session: 500
    calls_per_minute: 60
    tokens_per_session: 200000
    calls_per_tool: { fs.write_file: 50 }
  loop_guard:
    repeats: 10
  rules:                         # first match wins
    - id: no-destructive-shell
      tool: "shell.*"                              # glob, a|b alternation, or /regex/
      when:
        args.command: { regex: '\brm\s+-rf|\bgit\s+push\s+--force' }
      action: deny
      reason: "destructive shell command"

    - id: ask-before-anything-destructive
      tool: "*"
      when: { annotations.destructive: true }      # what the server says about itself
      action: ask

    - id: no-deploys-on-friday-afternoon
      tool: "*deploy*"
      when:
        time.weekday: { equals: "friday" }
        time.hour: { gt: 15 }
      action: deny
```

Matchers:

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

Paths: `args.path`, `args.items[*].sku`, `tool`, `upstream`, `annotations.destructive`, `time.hour`, `time.weekday`. The whole language, including what happens when a path is missing, is in [docs/policies.md](docs/policies.md).

Test a rule before you ship it:

```sh
agentgate check --tool 'shell.exec' --args '{"command":"rm -rf /"}'
agentgate check --tool 'deploy' --at 'friday 17:00'
agentgate policy validate agentgate.yaml
```

---

## Commands

<!-- BEGIN:commands -->
| Command | What it does |
|---|---|
| `check [flags]` | Dry-evaluate one call against the policy |
| `diff <session-a> <session-b> [flags]` | Compare two recorded sessions |
| `freeze [reason...]` | Stop every agent: deny all tool calls until unfreeze |
| `policy` | Work with the policy file |
| `policy suggest [flags]` | Write a deny-by-default policy from what the agent actually did |
| `policy validate [file]` | Check that a config file parses and its rules make sense |
| `replay <session-id> [flags]` | Re-run a recorded session through the current policy |
| `run [flags]` | Run the proxy |
| `sessions [flags]` | List recorded sessions |
| `show <session-id> [flags]` | Show the calls of one session |
| `stats [flags]` | What did the agent actually do? Per tool, per rule |
| `status` | Show the gateway's state at a glance |
| `tail [flags]` | Watch tool calls scroll by, live |
| `ui [flags]` | Browse the audit log in a browser |
| `unfreeze` | Lift the kill switch |
<!-- END:commands -->

Every flag: [docs/config.md](docs/config.md).

---

## Get it on your phone

```yaml
notify:
  webhooks:
    - url: https://ntfy.sh/my-agent          # or a Slack / Discord webhook URL
      format: ntfy                           # slack | discord | ntfy | json
      events: [deny, ask, honeypot, freeze]
```

A honeypot trip arrives as an urgent notification with the arguments the agent used. Arguments are redacted before they leave the machine.

---

## Documentation

| Document | What is in it |
|---|---|
| [docs/guardrails.md](docs/guardrails.md) | Kill switch, honeypots, loop guard, shadow mode, result redaction — how each one works and when to use it |
| [docs/policies.md](docs/policies.md) | The rule language in full |
| [docs/config.md](docs/config.md) | Every field of `agentgate.yaml`, every CLI flag |
| [docs/replay.md](docs/replay.md) | Replay, diff, stats, and the shadow → suggest → enforce workflow |
| [docs/architecture.md](docs/architecture.md) | How the proxy works, and what it deliberately does not do |
| [docs/comparison.md](docs/comparison.md) | Versus raw servers, wrapper scripts, host prompts and sandboxes |
| [docs/decisions.md](docs/decisions.md) | Design decisions and the reasoning behind each |

---

## Building from source

```sh
make build      # bin/agentgate
make test       # unit tests and policy golden files
make e2e        # the real binary in front of a real MCP server
make dev        # proxy + web UI against a demo server, nothing to install
make lint
```

---

## Status

v0.2. Everything in this README is implemented and covered by tests, including the end-to-end suite that drives the real binary. Not in it, on purpose: asking a model whether a call is safe (rules are deterministic so that `replay` can be trusted), central or multi-user management, governing prompts and resources (they pass through untouched), and authentication in front of the web UI (it refuses to bind to anything but localhost unless you insist).

Roadmap: a demo GIF for this page, per-session "allow for the rest of this session" approvals, and a `--record-only` mode.

## License

GPL-3.0-or-later — see [LICENSE](LICENSE).
