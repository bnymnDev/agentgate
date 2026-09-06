# Changelog

All notable changes to agentgate are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). Release notes with the full commit
list are on the [releases page](https://github.com/bnymnDev/agentgate/releases).

## [Unreleased]

### Added

- Social preview card, rendered from the same transcript as the demo recordings.
- CONTRIBUTING.md, SECURITY.md, issue and pull request templates, Dependabot
  configuration and this changelog.

### Changed

- Documentation refers to the current release instead of v0.1 where it
  described known limits.
- Hosts that open with `server/discover` (MCP protocol 2026-07-28) are
  recorded with their name and version like hosts that send `initialize`;
  before, such sessions showed an empty host and a tripped honeypot named
  an unknown host. Needed for go-sdk 1.7.0, which speaks that protocol.

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

[Unreleased]: https://github.com/bnymnDev/agentgate/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/bnymnDev/agentgate/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/bnymnDev/agentgate/releases/tag/v0.2.0
