# Where agentgate plugs in

agentgate is one binary with one config file. This document is about getting
it in front of the tools you already have — on your machine, in CI, in a
container — and getting what it sees out to the systems you already watch.

## MCP hosts: `agentgate init`

```sh
agentgate init          # what it would change, and nothing else
agentgate init --yes    # do it
```

`init` finds the MCP hosts on the machine and the servers each is configured
with:

| Host | Config file |
|---|---|
| Claude Desktop | `claude_desktop_config.json` in the user config directory |
| Claude Code | `.mcp.json` in the project |
| Cursor | `~/.cursor/mcp.json`, and `.cursor/mcp.json` in the project |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |
| VS Code | `.vscode/mcp.json` in the project |
| Gemini CLI | `~/.gemini/settings.json` |

For each host with servers, `--yes`:

1. writes `~/.agentgate/<host>.yaml` with the host's servers as upstreams —
   commands, arguments, environment, remote URLs and headers carried over —
   in shadow mode, with the `baseline`, `secrets` and `lethal-trifecta` packs,
   tool pinning and a honeypot, and next to it `<host>.test.yaml`, starter
   [tests](policies.md#testing-a-policy) for that policy;
2. replaces those servers in the host's config with one entry that runs
   agentgate by its absolute path;
3. keeps the original entries, byte for byte, in `~/.agentgate/installed.json`
   and a full copy of the file under `~/.agentgate/backup/`.

Only the servers member of the host's file is rewritten: every other setting
keeps its place and its value, VS Code's comments-and-trailing-commas JSON is
read, and servers marked disabled stay where they are. The generated config
holds the servers' environment, secrets included, so it is written readable
by you only.

Restart the host, and watch:

```sh
agentgate tail -c ~/.agentgate/claude-desktop.yaml
```

When the shadow decisions look right, set `policy.mode: enforce` in that file.

```sh
agentgate uninstall                  # every host init touched
agentgate uninstall cursor           # one
```

puts the servers back, keeping any that were added to the host in the
meantime. The agentgate configs and the audit log stay where they are.

By hand, the same thing is one line per server — wherever the host config
launches a server, launch agentgate instead:

```json
{ "command": "agentgate", "args": ["run", "--config", "/home/me/agentgate.yaml"] }
```

## Is it all working? `agentgate doctor`

```
agentgate 0.4.0 doctor

  ok    config     /home/me/.agentgate/cursor.yaml
  ok    audit      /home/me/.agentgate/audit.db (schema 0003_chain, 1204 calls, chain intact up to 1204)
  ok    upstream   filesystem: 14 tools over stdio
  fail  upstream   github: docker: not found
                   → install it, or give its absolute path in stdio:
  ok    policy     default allow, 21 rules (1 allow, 12 deny, 8 ask), packs baseline, secrets, lethal-trifecta
  warn  policy     shadow mode: decisions are recorded, nothing is blocked
  ok    pinning    warn mode, scan warn, 31 tools pinned, no drift
  info  canaries   none planted
                   → agentgate canary new --write <path> plants a fake credential that catches exfiltration
  ok    approvals  mode auto: phone (https://ntfy.sh), plus the web UI when it runs
  ok    hosts      Cursor: behind agentgate
```

`doctor` starts every upstream and asks it for its tools, so it finds the
server that will not start before your agent does; `--offline` only looks
the commands up. It exits 1 when a check fails.

## CI: the GitHub Action

An agent running in a workflow — a coding agent working an issue, a bot
triaging pull requests — has the same tools and the same problems as one on a
laptop, and nobody watching. Put agentgate in front of it:

```yaml
jobs:
  agent:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7

      # Installs agentgate, checksum-verified, and puts it on the PATH.
      # With a config, validates it, runs its policy tests, and fails the
      # step on a lint warning or a failing test.
      - uses: bnymnDev/agentgate@v0.4.0
        with:
          config: .github/agentgate.yaml

      # ... run the agent, with its MCP servers pointed at
      #     agentgate run --config .github/agentgate.yaml

      # Writes what the agent did to the job summary, verifies the audit
      # log's hash chain, and fails the job on a canary, a honeypot or a
      # quarantined tool.
      - uses: bnymnDev/agentgate/report@v0.4.0
        if: always()
        with:
          config: .github/agentgate.yaml
          fail-on: canary>0,honeypot>0,quarantine>0,denied>=25
```

| `bnymnDev/agentgate` input | Default | |
|---|---|---|
| `version` | `latest` | The release to install. |
| `config` | *(none)* | A config to validate and lint. |
| `lint` | `fail` | `fail`, `warn` or `off`: what a lint warning does. |
| `tests` | `auto` | The [policy tests](policies.md#testing-a-policy) to run: `auto` runs the file next to the config if there is one, `off` none; anything else names a test file. |
| `binary` | *(none)* | Use this binary instead of downloading one. |

| `bnymnDev/agentgate/report` input | Default | |
|---|---|---|
| `config` | required | The config the agent ran with. |
| `since` | `6h` | How far back to report. |
| `fail-on` | `canary>0,honeypot>0,quarantine>0` | Thresholds, as `agentgate stats --fail-on` takes them. Empty never fails. |
| `verify` | `true` | Verify the hash chain. |

The same checks work in any CI: `agentgate test` exits 1 when a policy test
fails, `agentgate stats --fail-on '…'` when a threshold is crossed,
`agentgate verify` on a broken chain, and `agentgate lock --check` when a
server changed a tool since the lockfile was committed.

## Containers

```sh
docker run --rm -v "$PWD:/etc/agentgate" -p 3333:3333 ghcr.io/bnymndev/agentgate:latest
```

The image — linux/amd64 and linux/arm64 — holds the agentgate binary alone, on
distroless, running as a non-root user. By default it serves MCP over HTTP on
`:3333` with `/etc/agentgate/agentgate.yaml`. That is enough for upstreams
reached over HTTP, for the web UI and for the reporting commands.

A stdio server has to be in the same container as agentgate, so copy the
binary into the image that has the server:

```dockerfile
FROM node:22-slim
RUN npm install -g @modelcontextprotocol/server-filesystem
COPY --from=ghcr.io/bnymndev/agentgate:latest /usr/local/bin/agentgate /usr/local/bin/agentgate
COPY agentgate.yaml /etc/agentgate/agentgate.yaml
ENTRYPOINT ["agentgate", "run", "--config", "/etc/agentgate/agentgate.yaml", "--http", ":3333"]
```

The `Dockerfile` at the root of the repository builds the same image from
source.

## OpenTelemetry

```yaml
telemetry:
  otlp:
    endpoint: http://localhost:4318
```

or only `OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318` in the
environment, and every tool call becomes a span — over OTLP/HTTP with JSON
encoding, which Jaeger, Tempo, Honeycomb, Datadog, Grafana Cloud and the
OpenTelemetry Collector all accept.

- Each session is one trace; each call is a span in it, named the way the MCP
  semantic conventions name them: `tools/call write_file`.
- Spans carry `gen_ai.tool.name`, `gen_ai.operation.name`, `mcp.method.name`
  and `mcp.session.id`, and agentgate's own: `agentgate.decision`,
  `agentgate.rule_id`, `agentgate.reason`, `agentgate.labels`,
  `agentgate.shadow`, `agentgate.upstream`, `agentgate.host.name`.
- A denied call, a failed one and a tool error get an error status, so a
  dashboard of denials is a query away.
- `OTEL_EXPORTER_OTLP_HEADERS`, `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`,
  `OTEL_SERVICE_NAME` and `OTEL_RESOURCE_ATTRIBUTES` are honoured.

Export is batched and off the request path; a slow or dead collector costs
spans, never calls.

## Tests: `agentgate mock`

```sh
agentgate mock 01JD7Z                   # stdio, for a host config or a test harness
agentgate mock 01JD7Z --http :3334
```

serves a recorded session as an MCP server: the same tools, under the same
names, from the session's catalog snapshot, answering every call with what the
real server answered at the time. A call is matched by tool and arguments;
repeated calls get the results in recorded order; a call that was never made
gets the tool's next recorded result, or with `--strict` an error. Nothing
real is behind it — no filesystem, no network, no side effects — so a real
session becomes a repeatable, offline fixture for an agent, a CI job or a new
policy.

Results are served as the audit log holds them: redacted, and a result cut at
`audit.max_result_bytes` cannot be served. Raise that limit for sessions you
want to mock.

## Your phone

Approvals and alerts both go through [ntfy](https://ntfy.sh): alerts with a
`notify.webhooks` entry of `format: ntfy`, approvals with `approval.ntfy`,
which puts Allow / Allow for session / Deny buttons on the notification. See
[guardrails.md](guardrails.md#approvals).
