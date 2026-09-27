# Changelog

All notable changes to agentgate are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). Release notes with the full commit
list are on the [releases page](https://github.com/bnymnDev/agentgate/releases).

## [Unreleased]

## [0.4.0] - 2026-09-27

agentgate stops being only a firewall for what the agent does and starts
watching the tools themselves: rug pulls, poisoned descriptions, planted
credentials on their way out, and instructions hidden in what a tool returns.

### Added

- Tool pinning. Every tool definition is pinned in a lockfile the first time
  it is seen; a later change is reported as drift, and with
  `pinning.mode: enforce` the tool is held back from the host until it is
  trusted. `agentgate lock` shows what changed, `--trust` accepts it,
  `--check` fails a CI job on it. A running gateway picks up a trusted tool
  from the lockfile without a restart.
- A scan of every tool definition for signs of poisoning: text hidden in
  Unicode tag characters (spelled out), zero-width, bidirectional and control
  characters, instructions addressed to the model, pointers at credentials and
  agent configuration, and one server's tool describing another server's.
  `pinning.scan: quarantine` holds a flagged tool back.
- Canaries. `agentgate canary new` plants a fake AWS, GitHub, OpenAI, Stripe
  or database credential, and optionally the decoy file that holds it; a call
  that carries one out is denied however it is encoded — plain, base64 at any
  alignment, URL-safe base64, hex, percent-encoded, JSON-escaped or reversed —
  and can freeze the gateway. `canaries.resource` advertises a decoy resource.
- Tool results are read for hidden text and instructions aimed at the model;
  such a result labels the session `injection-suspected` and fires the
  `injection` event. `policy.strip_invisible` removes the invisible characters
  before the model reads the result.
- Session labels: `policy.labels` attach facts to a session after a call went
  through, label rules may look at the result (`result.is_error`,
  `result.text`), and rules ask about them with `session.label.<name>`.
  agentgate attaches `injection-suspected` and `canary-read` itself.
- Selectors `host.name`, `host.version`, `session.labels`, `session.called` and
  `session.calls`; matchers `not_regex`, `includes` and `excludes`; `when` as a
  list of conditions; `"args.{command,cmd}"` for whichever member exists.
- Policy packs, switched on by name in `policy.packs`, with parameters:
  `baseline`, `secrets`, `lethal-trifecta`, `git-safety`, `github`,
  `database`, `filesystem`, `shell-strict`, `read-only`, `ask-destructive` and
  `business-hours`, or your own from a file. `agentgate policy packs`, `pack`,
  `add` and `remove`; `add` and `remove` edit only the lines of the list.
- `agentgate policy lint`: rules that can never fire, allow rules that let more
  through than they seem to, conditions on labels nothing attaches, and more.
- A tamper-evident audit log. Every call is chained to the one before it;
  `agentgate verify` proves no call was changed, removed or reordered, and
  `--anchor` also catches a cut-off end. Each session records a snapshot of
  the tools it was offered.
- Approvals on the phone through ntfy, with Allow, Allow for session and Deny
  buttons and a one-time nonce per question. A question goes to every channel
  at once — terminal, web UI, phone — and the first answer wins.
- OpenTelemetry: every call is a span over OTLP/HTTP, one trace per session,
  configured in `telemetry.otlp` or with the standard `OTEL_*` variables.
- `agentgate mock` serves a recorded session as an MCP server: the recorded
  tools and answers, nothing real behind them.
- `agentgate init` puts agentgate in front of the servers of Claude Desktop,
  Claude Code, Cursor, Windsurf, VS Code and Gemini CLI, in shadow mode;
  `agentgate uninstall` puts them back.
- `agentgate doctor` checks the config, the audit log and its chain, every
  upstream, pinning, canaries, approvals and the hosts.
- `agentgate stats --fail-on 'canary>0,denied>=25'` for CI.
- `upstreams[].tools` offers only the tools that match its globs; `!` patterns
  hide instead. A tool that is not offered never reaches the model.
- `agentgate check --label`, `--called`, `--host` and `--annotations`.
- Web UI: a live view, a tools page with what pinning and the scan found and a
  trust button, and the labels on sessions and calls.
- A container image, `ghcr.io/bnymndev/agentgate`, for linux/amd64 and
  linux/arm64, and a `Dockerfile` to build it from source.
- GitHub Actions: `bnymnDev/agentgate` installs agentgate and lints a config;
  `bnymnDev/agentgate/report` writes what the agent did to the job summary,
  verifies the chain and fails the job on a threshold.
- Webhook events `drift`, `exfiltration` and `injection`.
- `agentgate tail` shows the labels a call earned, and canaries and held tools
  as CANARY and HELD.
- Recordings of a rug pull and of an exfiltration attempt; the social preview
  card, rendered from a real session.
- CONTRIBUTING.md, SECURITY.md, issue and pull request templates, Dependabot
  configuration and this changelog.

### Changed

- `replay` evaluates each call as it was made: at its recorded time, for its
  recorded host, with the annotations and session history it had.
- The default webhook subscription is every event but `error` and `shadow`.
- `agentgate tail` fits the terminal's width and keeps its columns aligned with
  and without colour; `agentgate lock --color` shows hidden text in red.
- Hosts that open with `server/discover` (MCP protocol 2026-07-28) are
  recorded with their name and version like hosts that send `initialize`.
  Needed for go-sdk 1.7.0, which speaks that protocol.
- Documentation refers to the current release instead of v0.1 where it
  described known limits.

### Fixed

- An HTTP host was recorded as two sessions, one for its discovery request
  and one for its calls.
- Several processes opening a new audit database at once could fail with
  "database is locked".
- Table cells and `tail` lines no longer cut a multi-byte character in half.

## [0.3.0] - 2026-09-04

### Added

- Approvals can cover the rest of the session: answering "allow for this
  session" to an `ask` rule stops the same question from being asked again,
  in the terminal and in the web UI.
- `agentgate tail --color auto|always|never`.
- Demo recordings in `docs/demo`, rendered from real agentgate output with
  `make demo`.

## [0.2.0] - 2026-09-04

First tagged release. It contains the initial implementation and the guardrails
that were added on top of it.

### Added

- MCP passthrough proxy over stdio and HTTP with policy enforcement; tool names
  from several upstreams are prefixed to avoid collisions.
- Policy language in YAML: first-match rules with `allow`, `deny` and `ask`,
  glob, alternation and regex tool patterns, matchers on arguments, tool,
  upstream, server annotations and the clock; golden tests for the evaluator.
- SQLite audit store with secret redaction, `sessions`, `show`, `replay`
  (including `--dry-run` against the current policy) and `diff`.
- Kill switch: `freeze`, `unfreeze` and `status`.
- Honeypot tools that trip on use and can freeze the gateway.
- Loop guard, per-session, per-tool, per-minute and per-token budgets.
- Shadow mode, `stats` and `policy suggest` for the shadow, suggest, enforce
  workflow.
- Result redaction so that secrets never reach the model.
- Webhook notifications for Slack, Discord, ntfy and plain JSON.
- Embedded, server-rendered web UI with sessions, calls, the policy, the
  approvals inbox and the freeze button; refuses to bind to a non-loopback
  address unless told to.
- `check` and `policy validate` for testing rules before shipping them.
- End-to-end suite that drives the real binary in front of a real MCP server.
- Release pipeline with goreleaser: binaries for Linux, macOS and Windows on
  amd64 and arm64, and a Homebrew cask published from this repository.

### Fixed

- One reader goroutine per terminal approver.
- Windows-safe golden tests and SQLite DSN; LF-only fixtures.

[Unreleased]: https://github.com/bnymnDev/agentgate/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/bnymnDev/agentgate/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/bnymnDev/agentgate/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/bnymnDev/agentgate/releases/tag/v0.2.0
