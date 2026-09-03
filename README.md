# agentgate

**Firewall and flight recorder for your AI agent's tools.**

agentgate sits between an MCP host and the MCP servers it uses. Every `tools/call`
is checked against a YAML policy, written to a local audit log, and can be
replayed later against a different policy. Everything else — resources, prompts,
pings, logging — passes through untouched.

```
  MCP host                 agentgate                    MCP servers
┌────────────┐   stdio   ┌──────────────────┐  stdio  ┌──────────────┐
│  your      │──────────▶│ policy   audit   │────────▶│ filesystem   │
│  agent     │◀──────────│ ├ allow  ├ sqlite│◀────────│ shopware     │
└────────────┘           │ ├ deny   └ replay│  http   │ your own one │
                         │ └ ask            │────────▶└──────────────┘
                         └──────────────────┘
```

No changes to the host. No changes to the servers. One binary, no cgo, no
runtime dependencies.

---

## Why

An MCP server is a set of functions you have handed to a language model. Most of
them are fine. A few of them delete things, spend money or push to `main`. Today
your options are to trust the model, to not install the server, or to wrap it in
a shell script you will forget about.

agentgate gives you a third option: keep the server, put a rule in front of the
handful of calls that scare you, and keep a record of everything that happened.

```yaml
- id: no-destructive-shell
  tool: "shell.*"
  when:
    args.command: { regex: '\brm\s+-rf|\bgit\s+push\s+--force' }
  action: deny
  reason: "destructive shell command"
```

The agent does not get a broken connection. It gets a tool result it can read:

```
agentgate denied: destructive shell command (rule no-destructive-shell)
```

…and adapts, which is the whole point.

---

## Install

```sh
go install github.com/bnymnDev/agentgate/cmd/agentgate@latest
# or
brew install bnymnDev/tap/agentgate
```

Prebuilt binaries for linux, macOS and Windows (amd64 and arm64) are on the
[releases page](https://github.com/bnymnDev/agentgate/releases).

---

## 30-second setup

**1. Write `agentgate.yaml`** next to wherever you keep your host config:

```yaml
version: 1

audit:
  path: ~/.agentgate/audit.db
  retention: 30d

upstreams:
  - name: fs
    stdio: ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/home/me/repo"]

policy:
  default: allow
  rules:
    - id: stay-in-the-repo
      tool: "fs.write_file"
      when:
        args.path: { not_prefix: "/home/me/repo/" }
      action: deny
      reason: "writes are confined to the repository"
```

**2. Point the host at agentgate instead of the server.** Wherever your host
config used to say

```json
{ "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/home/me/repo"] }
```

say this instead:

```json
{ "command": "agentgate", "args": ["run", "--stdio", "--config", "/home/me/agentgate.yaml"] }
```

Any MCP host that can launch a stdio server works. The config file lives at:

| Host | Config file |
|---|---|
| Claude Code | `.mcp.json` in the project, or `claude mcp add` |
| Claude Desktop | `claude_desktop_config.json` |
| Cursor | `.cursor/mcp.json` |
| Anything else | wherever it keeps its `mcpServers` map |

**3. Watch it work.**

```sh
agentgate sessions
agentgate show 01JD8K2M          # a table of every call
agentgate ui                     # the same thing in a browser
```

---

## What you get

| | |
|---|---|
| **Policy** | Glob or regex on tool names, JSONPath-lite on arguments, eight matchers, first match wins. |
| **Three verdicts** | `allow`, `deny`, and `ask` — which parks the call until a human clicks or types `y`. |
| **Budgets** | A cap per session and per tool. Checked before the rules, so nothing can lift one. |
| **Audit log** | Local SQLite. Arguments, results, decisions, durations, token estimates, sha256 hashes. |
| **Redaction** | Secrets are scrubbed before they are written, never after. Built-in patterns plus your own. |
| **Replay** | Re-run yesterday's real session against today's policy and see exactly what changes. |
| **Diff** | Compare two sessions call by call, aligned so an inserted call does not shift everything. |
| **Web UI** | Server-rendered, embedded in the binary, no CDN, no Node, dark and light. |
| **Multiple servers** | Front several MCP servers as one merged tool list, prefixed by server name. |
| **Transparent** | With no matching rule, bytes in equal bytes out. Resources and prompts are never touched. |

---

## The killer feature: replay

You have a session from yesterday where the agent did something you did not
expect. You write a rule. Now you want to know whether that rule would have
caught it — and what else it would have broken.

```sh
agentgate replay 01JD8K2M --dry-run
```

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

Nothing leaves the machine. Drop `--dry-run` and the allowed calls are actually
re-sent, and the fresh results are compared with the recorded ones by hash.

---

## Commands

<!-- BEGIN:commands -->
| Command | What it does |
|---|---|
| `check [flags]` | Dry-evaluate one call against the policy |
| `diff <session-a> <session-b> [flags]` | Compare two recorded sessions |
| `policy` | Work with the policy file |
| `policy validate [file]` | Check that a config file parses and its rules make sense |
| `replay <session-id> [flags]` | Re-run a recorded session through the current policy |
| `run [flags]` | Run the proxy |
| `sessions [flags]` | List recorded sessions |
| `show <session-id> [flags]` | Show the calls of one session |
| `ui [flags]` | Browse the audit log in a browser |
<!-- END:commands -->

Full flag reference: [docs/config.md](docs/config.md).

---

## Writing policies

Rules are evaluated top to bottom and the first match wins. A rule matches when
its `tool` pattern matches **and** every condition in `when` holds.

```yaml
policy:
  default: allow            # or deny, for a locked-down setup
  budget:
    calls_per_session: 500
    calls_per_tool:
      fs.write_file: 50
  rules:
    - id: shopware-writes-need-approval
      tool: "shopware.*"
      when:
        args.dryRun: { equals: false }
      action: ask
      reason: "this would change live shop data"
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

The full reference — tool patterns, argument paths, array wildcards, budgets,
and what happens when a path is missing — is in
[docs/policies.md](docs/policies.md).

Check a rule before you ship it:

```sh
agentgate check --tool 'shopware.stock_set' --args '{"stock":0,"dryRun":false}'
agentgate policy validate agentgate.yaml
```

---

## Documentation

| Document | What is in it |
|---|---|
| [docs/config.md](docs/config.md) | Every field of `agentgate.yaml`, every CLI flag |
| [docs/policies.md](docs/policies.md) | The rule language in full |
| [docs/replay.md](docs/replay.md) | Replay and diff, and how to use them to test a policy |
| [docs/architecture.md](docs/architecture.md) | How the proxy works, and what it deliberately does not do |
| [docs/comparison.md](docs/comparison.md) | Versus running servers raw, versus wrapper scripts |
| [docs/decisions.md](docs/decisions.md) | Design decisions and why they went that way |

---

## Building from source

```sh
make build      # bin/agentgate
make test       # unit tests and policy golden files
make e2e        # the real binary in front of a real MCP server
make dev        # the proxy plus the web UI against a demo server
make lint
```

`make dev` needs nothing installed: it builds a small demo MCP server from
`testdata/servers/echo`, puts agentgate in front of it, and opens the proxy on
`127.0.0.1:3333` with the UI on `127.0.0.1:7777`.

---

## Status and roadmap

v0.1 is feature complete. What is deliberately **not** in it: asking a model whether a call looks safe, central or multi-user
management, governing prompts and resources, and authentication in front of the
web UI (keep it on localhost).

- [x] stdio and Streamable HTTP on both sides, multiple upstreams, prefixing
- [x] policy model, evaluator, golden tests, budgets, `check`, `policy validate`
- [x] SQLite audit store with redaction, retention and result caps
- [x] `sessions`, `show`, `replay`, `diff`, embedded web UI, hot reload
- [x] approvals over the terminal and over the web UI
- [ ] a demo GIF for this README
- [ ] approval rules that remember a decision for the rest of a session
- [ ] a `--record-only` mode for a first pass with no policy at all

---

## License

GPL-3.0-or-later — see [LICENSE](LICENSE).
