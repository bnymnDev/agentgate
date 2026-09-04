# Configuration

agentgate reads one YAML file. Unknown keys are an error, so a typo is caught by
`agentgate policy validate` rather than silently ignored at run time.

The file is looked for in this order when `--config` is not given:

1. `./agentgate.yaml`, then `./agentgate.yml`
2. `~/.agentgate/agentgate.yaml`
3. `~/.config/agentgate/agentgate.yaml`

## A complete file

```yaml
version: 1                       # required, must be 1

prefix_separator: "__"           # joins upstream name and tool name
call_timeout: 120s               # per call, unless an upstream overrides it

approval:
  mode: auto                     # auto | tty | ui | deny
  timeout: 60s                   # after this, an unanswered "ask" is denied

audit:
  enabled: true
  path: ~/.agentgate/audit.db
  retention: 30d                 # sessions older than this are pruned on startup
  max_result_bytes: 262144       # results above this are truncated and flagged
  builtin_redaction: true        # keep the built-in secret patterns
  redact:                        # your own patterns, added to the built-in ones
    - '(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*\S+'

upstreams:
  - name: fs
    stdio: ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/home/me/repo"]
    env: { LOG_LEVEL: "warn" }
    cwd: /home/me/repo
    prefix: true
    timeout: 30s

  - name: github
    stdio: ["npx", "-y", "@modelcontextprotocol/server-github"]
    env: { GITHUB_PERSONAL_ACCESS_TOKEN: "${GITHUB_TOKEN}" }

  - name: remote
    http: https://mcp.example.com/mcp
    headers: { Authorization: "Bearer ${REMOTE_TOKEN}" }
    prefix: false

honeypots:
  action: freeze                 # deny | freeze — what tripping one does
  tools:
    - name: db__drop_all_tables
      description: "Drop every table in the production database. Irreversible."

notify:
  webhooks:
    - url: https://ntfy.sh/my-agent
      format: ntfy               # json | slack | discord | ntfy
      events: [deny, ask, honeypot, freeze]
    - url: https://hooks.slack.com/services/T000/B000/XXXX
      format: slack
      headers: {}

policy:
  default: allow
  mode: enforce                  # enforce | shadow
  redact_results: false
  budget:
    calls_per_session: 500
    calls_per_minute: 60
    tokens_per_session: 200000
    calls_per_tool:
      fs.write_file: 50
  loop_guard:
    repeats: 10
  rules: []                      # see docs/policies.md
```

## Top level

| Field | Default | What it does |
|---|---|---|
| `version` | `1` | Config format version. Only `1` exists. |
| `prefix_separator` | `"__"` | What joins an upstream name to a tool name. See below. |
| `call_timeout` | `120s` | How long a `tools/call` may take before agentgate gives up. |

Durations accept `d` and `w` on top of what Go understands: `30d`, `2w`, `1h30m`,
`500ms`.

### Why `__` and not `.`

The MCP specification does not restrict tool-name characters, but several hosts
inherited the OpenAI function-calling constraint of `^[a-zA-Z0-9_-]{1,64}$`, in
which a dot is invalid. `__` is safe everywhere, so it is the default.

You never have to care about this when writing rules: a rule pattern is matched
against both the exposed name and the canonical `upstream.tool` spelling, so

```yaml
tool: "fs.write_file"     # matches fs__write_file, fs.write_file, fs/write_file…
```

keeps working whatever the separator is set to.

## `approval`

What happens to a call a rule marked `ask`.

| Mode | Behaviour |
|---|---|
| `auto` | Use the web UI if it is running, otherwise the terminal, otherwise deny. The default. |
| `ui` | Wait for a click in the web UI. Denies if the UI is not running. |
| `tty` | Prompt on agentgate's terminal. Denies if there is no terminal. |
| `deny` | Never ask. Every `ask` becomes a deny with a reason that says so. |

In stdio mode stdin and stdout carry MCP traffic, so agentgate opens the
controlling terminal (`/dev/tty`, `CONIN$` on Windows) for the prompt. If there
is none — which is the normal case when a host launches agentgate as a
subprocess — `ask` denies with `approval required, no TTY`. To actually approve
things, run with `--ui` and use the approvals inbox, or run in `--http` mode.

Both channels offer three answers:

| Terminal | Web UI | Effect |
|---|---|---|
| `y` | Allow once | this call goes through; the next one asks again |
| `a` | Allow for this session | this call and every later call of the **same tool** in the **same session** go through without asking |
| `n` (or nothing) | Deny | the call is denied with a reason that says who rejected it |

A session-wide approval is keyed by tool name, not by arguments, and dies
with the session. The audit log records the rule that asked on every call it
covered, with the reason `approved earlier for the rest of this session`.

## `audit`

| Field | Default | What it does |
|---|---|---|
| `enabled` | `true` | Set to `false` to run with no audit trail at all. |
| `path` | `~/.agentgate/audit.db` | SQLite file. `~` and `${ENV}` are expanded; the directory is created. |
| `retention` | `30d` | Sessions older than this are deleted when agentgate starts. |
| `max_result_bytes` | `262144` | Results larger than this are stored truncated and flagged. The hash is still of the whole result. |
| `builtin_redaction` | `true` | Whether the built-in secret patterns apply. |
| `redact` | *(empty)* | Your own regexes, added to the built-in ones. |

Audit writes are asynchronous and best effort. If the database is unavailable,
the call still happens; the failure is logged and counted. Auditing can never
delay or fail a tool call.

### Built-in redaction patterns

These are applied to every recorded call unless `builtin_redaction: false`:

<!-- BEGIN:redactions -->
```
(?i)\b(api[_-]?key|apikey|secret|token|password|passwd|pwd|authorization|auth[_-]?token|access[_-]?key|private[_-]?key|client[_-]?secret)\b\s*[:=]\s*\S+
(?i)\bbearer\s+[A-Za-z0-9\-._~+/]{12,}=*
\bAKIA[0-9A-Z]{16}\b
\bgh[pousr]_[A-Za-z0-9]{16,}\b
\bsk-[A-Za-z0-9]{16,}\b
\bxox[abprs]-[A-Za-z0-9-]{10,}\b
-----BEGIN[A-Z ]*PRIVATE KEY-----
\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b
```
<!-- END:redactions -->

How a pattern is applied is described in [architecture.md](architecture.md#redaction).

## `upstreams`

One entry per real MCP server. Exactly one of `stdio` and `http` is required.

| Field | What it does |
|---|---|
| `name` | Identifies the upstream in prefixes, rules and the audit log. Required, unique. |
| `stdio` | Command and arguments, as a list. `${ENV}` is expanded in every element. |
| `http` | Streamable HTTP endpoint. |
| `env` | Added to the environment of a stdio server. Values are `${ENV}`-expanded. |
| `cwd` | Working directory of a stdio server. |
| `headers` | Sent with every request to an HTTP server. Values are `${ENV}`-expanded. |
| `prefix` | Whether to prefix this server's tools. Defaults to `false` for a single upstream and `true` for several. |
| `timeout` | Overrides `call_timeout` for this server. |

`${VAR}` and `$VAR` are expanded from agentgate's own environment in `stdio`
arguments, `env` values, `headers` values, `http` and `audit.path` — and nowhere
else, so a `$` in a policy regex means what it says.

An upstream that fails to connect is logged and skipped; the rest still come up.
agentgate only refuses to start when *no* upstream can be reached.

## `honeypots`

Decoy tools that exist only to be called by an agent that should not be
calling anything you did not ask for. See
[guardrails.md](guardrails.md#honeypot-tools).

| Field | Default | What it does |
|---|---|---|
| `action` | `deny` | `deny` records and denies; `freeze` also throws the kill switch. |
| `tools[].name` | required | The exact name the host sees. Use a real upstream's prefix to blend in. |
| `tools[].description` | a generic one | What the host shows the model. Make it convincing. |

## `notify`

Webhooks that hear about events. See [guardrails.md](guardrails.md#notifications).

| Field | Default | What it does |
|---|---|---|
| `webhooks[].url` | required | An absolute http(s) URL. `${ENV}` is expanded. |
| `webhooks[].format` | `json` | `json` posts agentgate's event object; `slack`, `discord`, `ntfy` post what those services render. |
| `webhooks[].events` | `deny, ask, honeypot, freeze` | Any of `deny`, `ask`, `honeypot`, `freeze`, `error`, `shadow`. |
| `webhooks[].headers` | *(none)* | Sent with every request. Values are `${ENV}`-expanded. |

## `policy`

See [policies.md](policies.md).

## The kill switch marker

`agentgate freeze` writes a marker file next to the audit database —
`FROZEN` in the same directory as `audit.path`. Every gateway that reads this
config checks for it on every call. `agentgate status` prints the path.

## CLI flags

<!-- BEGIN:flags -->
### Global flags

| Flag | What it does | Default |
|---|---|---|
| `--log-level` | log level: debug, info, warn or error | `info` |
| `-c, --config` | path to agentgate.yaml (default: ./agentgate.yaml, then ~/.agentgate/agentgate.yaml) |  |

### `check [flags]`

| Flag | What it does | Default |
|---|---|---|
| `--args` | tool arguments as a JSON object |  |
| `--at` | evaluate as if the call were made at this time, e.g. "2026-09-04 16:30" or "friday 17:00", to test time rules |  |
| `--calls-so-far` | pretend this many calls were already made, to test budgets | `0` |
| `--json` | print the call and the decision as JSON |  |
| `--repeats` | pretend the identical call was just made this many times, to test the loop guard | `0` |
| `--tool` | tool name as the host sees it, prefix included |  |

### `diff <session-a> <session-b> [flags]`

| Flag | What it does | Default |
|---|---|---|
| `--all` | also list calls that are identical |  |
| `--json` | print the diff as JSON |  |

### `policy suggest [flags]`

| Flag | What it does | Default |
|---|---|---|
| `--loop-guard` | loop_guard.repeats to include; 0 to leave it out | `10` |
| `--out` | write the policy to this file instead of stdout |  |
| `--session` | learn from one session instead (id or prefix) |  |
| `--since` | window to learn from, e.g. 24h, 7d; empty for everything | `7d` |

### `replay <session-id> [flags]`

| Flag | What it does | Default |
|---|---|---|
| `--dry-run` | only re-evaluate the policy, send nothing |  |
| `--json` | print the report as JSON |  |
| `--only-allowed` | skip calls that were denied when they were recorded |  |

### `run [flags]`

| Flag | What it does | Default |
|---|---|---|
| `--allow-remote-ui` | allow the web UI to bind to a non-loopback address (it has no authentication) |  |
| `--http` | serve MCP over Streamable HTTP on this address, e.g. :3333 |  |
| `--stdio` | serve MCP on stdin/stdout (the default) |  |
| `--ui` | also serve the web UI on this address, e.g. 127.0.0.1:7777 |  |

### `sessions [flags]`

| Flag | What it does | Default |
|---|---|---|
| `--json` | print as JSON |  |
| `--limit` | maximum number of sessions to list | `50` |
| `--since` | only sessions started within this window, e.g. 24h or 7d |  |

### `show <session-id> [flags]`

| Flag | What it does | Default |
|---|---|---|
| `--args` | show the arguments instead of the reason |  |
| `--decision` | only calls with this decision: allow, deny or ask |  |
| `--json` | print as JSON |  |
| `--tool` | only calls whose tool name contains this |  |

### `stats [flags]`

| Flag | What it does | Default |
|---|---|---|
| `--json` | print as JSON |  |
| `--markdown` | print as Markdown tables |  |
| `--session` | summarise one session instead (id or prefix) |  |
| `--since` | window to summarise, e.g. 1h, 24h, 7d; empty for everything | `24h` |
| `--top` | how many tools to list | `25` |

### `tail [flags]`

| Flag | What it does | Default |
|---|---|---|
| `--args` | show the arguments on every line |  |
| `--color` | colour the output: auto, always or never | `auto` |
| `--json` | one JSON object per line |  |
| `--last` | how many recent calls to show before following | `20` |
| `--no-follow` | print the recent calls and exit |  |
| `--session` | only calls of this session (id or prefix) |  |

### `ui [flags]`

| Flag | What it does | Default |
|---|---|---|
| `--addr` | address to listen on | `127.0.0.1:7777` |
| `--allow-remote-ui` | allow binding to a non-loopback address (the UI has no authentication) |  |
<!-- END:flags -->
