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
  mode: auto                     # auto | tty | ui | ntfy | deny
  timeout: 60s                   # after this, an unanswered "ask" is denied
  ntfy:                          # optional: approve on your phone
    topic: agentgate-7f3a9c2e41b8d605
    server: https://ntfy.sh
    token: ${NTFY_TOKEN}

audit:
  enabled: true
  path: ~/.agentgate/audit.db
  retention: 30d                 # calls older than this are pruned on startup
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
    tools: ["get_*", "list_*", "search_*", create_pull_request]   # offer only these

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
      events: [deny, ask, honeypot, freeze, drift, exfiltration, injection]
    - url: https://hooks.slack.com/services/T000/B000/XXXX
      format: slack
      headers: {}

pinning:
  mode: warn                     # warn | enforce | off
  scan: warn                     # warn | quarantine | off
  lockfile: agentgate.lock       # default: next to this file, same name

canaries:
  action: freeze                 # deny | freeze
  path: ~/.agentgate/canaries.json
  resource: file:///home/me/.aws/credentials   # optional decoy resource

telemetry:
  otlp:
    endpoint: http://localhost:4318
    headers: { x-honeycomb-team: "${HONEYCOMB_KEY}" }
    service_name: agentgate

policy:
  default: allow
  mode: enforce                  # enforce | shadow
  redact_results: false
  strip_invisible: false
  packs: [baseline, secrets, lethal-trifecta]
  labels: []                     # see docs/policies.md
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
| `auto` | Ask on every channel there is at once — the web UI if it is running, the terminal if there is one, the phone if `ntfy` is set — and take the first answer. Deny if there is no channel. The default. |
| `ui` | Wait for a click in the web UI. Denies if the UI is not running. |
| `tty` | Prompt on agentgate's terminal. Denies if there is no terminal. |
| `ntfy` | Ask on the phone only. |
| `deny` | Never ask. Every `ask` becomes a deny with a reason that says so. |

In stdio mode stdin and stdout carry MCP traffic, so agentgate opens the
controlling terminal (`/dev/tty`, `CONIN$` on Windows) for the prompt. If there
is none — which is the normal case when a host launches agentgate as a
subprocess — the terminal is not a channel. Run with `--ui` and use the
approvals inbox, run in `--http` mode, or put the questions on your phone:

| `approval.ntfy` | Default | What it does |
|---|---|---|
| `topic` | required | Where the questions go; answers come back on `<topic>-answers`. On a public server the topic name is the password: at least 16 random characters, unless a token protects it. |
| `server` | `https://ntfy.sh` | The ntfy server, public or your own. |
| `token` | *(none)* | An access token for a server with access control. `${ENV}` is expanded. |

See [guardrails.md](guardrails.md#approvals) for how an answer gets back.

Every channel offers three answers:

| Terminal | Web UI, phone | Effect |
|---|---|---|
| `y` | Allow | this call goes through; the next one asks again |
| `a` | Allow for session | this call and every later call of the **same tool** in the **same session** go through without asking |
| `n` (or nothing) | Deny | the call is denied with a reason that says who rejected it |

A session-wide approval is keyed by tool name, not by arguments, and dies
with the session. The audit log records the rule that asked on every call it
covered, with the reason `approved earlier for the rest of this session`.

## `audit`

| Field | Default | What it does |
|---|---|---|
| `enabled` | `true` | Set to `false` to run with no audit trail at all. |
| `path` | `~/.agentgate/audit.db` | SQLite file. `~` and `${ENV}` are expanded; the directory is created. |
| `retention` | `30d` | Calls older than this are deleted when agentgate starts, from the front of the hash chain only, and so are sessions left with no calls. |
| `max_result_bytes` | `262144` | Results larger than this are stored truncated and flagged. The hash is still of the whole result. |
| `builtin_redaction` | `true` | Whether the built-in secret patterns apply. |
| `redact` | *(empty)* | Your own regexes, added to the built-in ones. |

Audit writes are asynchronous and best effort. If the database is unavailable,
the call still happens; the failure is logged and counted. Auditing can never
delay or fail a tool call.

Every call is a link in a hash chain; `agentgate verify` walks it. Several
agentgate processes can share one database and still build one chain. The
database also keeps each distinct tool catalog once, and which one every
session and call saw — what replay and `agentgate mock` use.

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
| `tools` | Offer only the tools matching these globs, by the server's own names for them. A pattern starting with `!` hides what it matches. Empty offers everything. |

`tools` is the smallest attack surface there is. A server with forty tools
puts forty descriptions in front of the model, and the model reads every one
of them as instructions — including the tools it never needed. A tool that is
not offered is not listed, cannot be called, and its description never
reaches the model, the lockfile or the audit log:

```yaml
tools: [get_issue, "list_*"]              # only these
tools: ["!delete_*", "!merge_pull_request"]   # everything but these
tools: ["*_issue*", "!delete_*"]          # issues, but never deleting one
```

`agentgate doctor` warns about a pattern that matches none of the server's
tools. Like every other upstream field, `tools` is read when agentgate
starts.

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
| `webhooks[].events` | all but `error` and `shadow` | Any of `deny`, `ask`, `honeypot`, `freeze`, `drift`, `exfiltration`, `injection`, `error`, `shadow`. |
| `webhooks[].headers` | *(none)* | Sent with every request. Values are `${ENV}`-expanded. |

## `pinning`

Pins every tool definition in a lockfile and scans it for tool poisoning. See
[guardrails.md](guardrails.md#tool-pinning-rug-pulls).

| Field | Default | What it does |
|---|---|---|
| `mode` | `warn` | `warn` pins and reports changes; `enforce` also hides changed and new tools from the host until they are trusted; `off` keeps no lockfile. |
| `scan` | `warn` | `warn` reports what the definition scan finds; `quarantine` hides a flagged tool until it is trusted; `off` does not scan. |
| `lockfile` | the config's name with `.lock` | Relative paths are relative to the config. `agentgate lock` reviews and trusts what is in it. |

## `canaries`

Fake credentials agentgate watches for. See [guardrails.md](guardrails.md#canaries).

| Field | Default | What it does |
|---|---|---|
| `action` | `deny` | `deny` stops and reports a call carrying a canary out; `freeze` also throws the kill switch. |
| `path` | `canaries.json` next to the audit database | Where `agentgate canary new` keeps them. |
| `resource` | *(none)* | A URI to advertise a decoy MCP resource under; its content is the canaries' decoy files. |

## `telemetry`

Exports a span per tool call. See [integrations.md](integrations.md#opentelemetry).

| Field | Default | What it does |
|---|---|---|
| `otlp.endpoint` | `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP/HTTP base URL; spans go to `<endpoint>/v1/traces`. Setting the environment variable alone switches export on. |
| `otlp.headers` | `OTEL_EXPORTER_OTLP_HEADERS` | Sent with every export, e.g. an API key. The file wins over the environment. |
| `otlp.service_name` | `agentgate` | Or `OTEL_SERVICE_NAME`. |

## `policy`

See [policies.md](policies.md). The fields that are not rules:

| Field | Default | What it does |
|---|---|---|
| `default` | `allow` | The decision when no rule matches: `allow` or `deny`. |
| `mode` | `enforce` | `shadow` records decisions and blocks nothing. |
| `redact_results` | `false` | Scrub secrets from results before the agent reads them. |
| `strip_invisible` | `false` | Remove invisible and reordering characters from results before the agent reads them. |
| `packs` | *(none)* | Rule sets to switch on, by name or file. |
| `labels` | *(none)* | Label rules. |
| `budget`, `loop_guard` | *(off)* | Hard stops before the rules. |

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

### `canary list [flags]`

| Flag | What it does | Default |
|---|---|---|
| `--json` | print as JSON, values included |  |

### `canary new [flags]`

| Flag | What it does | Default |
|---|---|---|
| `--force` | overwrite the --write file if it exists |  |
| `--kind` | what the canary looks like: aws, github, openai, stripe, password | `aws` |
| `--label` | a name to recognise it by in alerts |  |
| `--write` | write a decoy file holding the canary to this path |  |

### `canary rm <id-or-label> [flags]`

| Flag | What it does | Default |
|---|---|---|
| `--delete-file` | also delete the decoy file it was written to |  |

### `check [flags]`

| Flag | What it does | Default |
|---|---|---|
| `--annotations` | what the server says about the tool, e.g. read_only=true,destructive=false |  |
| `--args` | tool arguments as a JSON object |  |
| `--at` | evaluate as if the call were made at this time, e.g. "2026-09-04 16:30" or "friday 17:00", to test time rules |  |
| `--called` | a tool the session already called, as upstream.tool (repeatable) |  |
| `--calls-so-far` | pretend this many calls were already made, to test budgets | `0` |
| `--host` | the host that opened the session, as name or name/version, to test host.* rules |  |
| `--json` | print the call and the decision as JSON |  |
| `--label` | a label the session already carries (repeatable) |  |
| `--repeats` | pretend the identical call was just made this many times, to test the loop guard | `0` |
| `--tool` | tool name as the host sees it, prefix included |  |

### `diff <session-a> <session-b> [flags]`

| Flag | What it does | Default |
|---|---|---|
| `--all` | also list calls that are identical |  |
| `--json` | print the diff as JSON |  |

### `doctor [flags]`

| Flag | What it does | Default |
|---|---|---|
| `--json` | print the checks as JSON |  |
| `--offline` | do not start the upstream servers or reach out to the network |  |

### `init [flags]`

| Flag | What it does | Default |
|---|---|---|
| `--dir` | where agentgate keeps its configs and the manifest (default ~/.agentgate) |  |
| `--host` | only this host (repeatable): claude-desktop, claude-code, cursor, cursor-project, windsurf, vscode, gemini-cli |  |
| `--yes` | make the changes instead of showing them |  |

### `lock [flags]`

| Flag | What it does | Default |
|---|---|---|
| `--check` | exit 1 if any tool is new, changed, removed, unpinned or flagged |  |
| `--color` | colour the output: auto, always or never | `auto` |
| `--json` | print the reports as JSON |  |
| `--trust` | trust a tool as it is offered now, as upstream.tool; '*' trusts everything (repeatable) |  |

### `mock <session-id> [flags]`

| Flag | What it does | Default |
|---|---|---|
| `--http` | serve over Streamable HTTP on this address instead of stdio |  |
| `--strict` | answer calls that were never recorded with an error instead of the tool's next recorded result |  |

### `policy add <pack> [flags]`

| Flag | What it does | Default |
|---|---|---|
| `--with` | a value for one of the pack's parameters, as key=value (repeatable) |  |

### `policy lint [file] [flags]`

| Flag | What it does | Default |
|---|---|---|
| `--connect` | ask the servers for their tools instead of using the last recorded catalog |  |
| `--json` | print the findings as JSON |  |

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
| `--fail-on` | exit 1 when a threshold is crossed, e.g. 'canary>0,denied>=10' |  |
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

### `test [file...] [flags]`

| Flag | What it does | Default |
|---|---|---|
| `--color` | colour the output: auto, always or never | `auto` |
| `--from` | write a test from a recorded session (id or prefix) to stdout, instead of running tests (repeatable) |  |
| `--json` | print the outcomes as JSON |  |
| `--missing-ok` | succeed when no file is named and the default test file does not exist |  |
| `--run` | only the tests whose names match this regular expression |  |

### `ui [flags]`

| Flag | What it does | Default |
|---|---|---|
| `--addr` | address to listen on | `127.0.0.1:7777` |
| `--allow-remote-ui` | allow binding to a non-loopback address (the UI has no authentication) |  |

### `uninstall [host...] [flags]`

| Flag | What it does | Default |
|---|---|---|
| `--dir` | where agentgate keeps its configs and the manifest (default ~/.agentgate) |  |

### `verify [flags]`

| Flag | What it does | Default |
|---|---|---|
| `--anchor` | a head printed by an earlier verify, as seq:hash, that must still be in the chain |  |
| `--json` | print the report as JSON |  |
| `--missing-ok` | succeed when there is no audit database yet, instead of failing |  |
<!-- END:flags -->
