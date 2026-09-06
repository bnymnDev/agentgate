# Contributing to agentgate

Thank you for taking the time to contribute. agentgate is a small, deliberately
scoped project; this page describes how to build it, how to test it and what a
good change looks like.

## Prerequisites

- Go, at the version pinned in [`go.mod`](go.mod). CI uses exactly that version.
- `make` (optional; every target is a plain `go` command you can run by hand).
- [golangci-lint](https://golangci-lint.run/welcome/install/) v2 for `make lint`.
  CI pins the version in [`.github/workflows/ci.yaml`](.github/workflows/ci.yaml).
- [goreleaser](https://goreleaser.com/install/) only if you want to build
  release artifacts locally with `make release-snapshot`.

No cgo is needed: the SQLite driver is pure Go, so `CGO_ENABLED=0` builds work
on every platform.

## Building

```sh
make build            # bin/agentgate, with version information from git
go build ./cmd/agentgate   # the same without ldflags
make install          # go install into GOBIN
make dev              # proxy + web UI against the demo server in testdata/servers
```

## Testing

```sh
make test             # unit tests and policy golden files
make e2e              # builds the binaries and drives them as real processes
make coverage         # unit tests with a coverage profile
make vet              # go vet, including the e2e build tag
make lint             # golangci-lint
make fmt              # gofmt every package
```

Details worth knowing:

- **Golden files.** The policy evaluator is tested against fixtures in
  `testdata/calls` and expected decisions in `testdata/golden`. If you change
  evaluation on purpose, run `make golden`, read the diff it prints and commit
  the updated files together with the change.
- **End-to-end suite.** `e2e/` builds the real binary and a real MCP server and
  talks to them over stdio. It is behind the `e2e` build tag so that
  `go test ./...` stays fast; run it with `make e2e` before opening a pull
  request that touches the proxy, the CLI or the audit store.
- **Generated documentation.** The tables between `<!-- BEGIN:name -->` and
  `<!-- END:name -->` markers in `README.md` and `docs/` are produced by
  `make docs` from the CLI and policy definitions. Do not edit them by hand;
  change the source, run `make docs` and commit the result. CI fails if the
  generated text drifts.
- **Demo recordings.** The GIFs in `docs/demo` are rendered from the
  transcripts next to them with `make demo`. Update the transcript, not the GIF.

CI runs the unit tests with `-race` on Linux, macOS and Windows, the e2e suite,
the docs drift check and golangci-lint. A change is ready when all of them
pass.

## Conventions

- Format with `gofmt`; keep `go vet` and golangci-lint clean. The linter
  configuration in [`.golangci.yaml`](.golangci.yaml) documents the few
  deliberate exclusions.
- Follow the design principles in the README: transparent by default, every
  decision carries a reason, evaluation is pure, fail closed and audit
  best-effort, one binary. A change that needs a network call, a clock or the
  filesystem inside the policy evaluator is probably in the wrong place.
- Keep exported identifiers documented; `revive` checks for it.
- Commit messages use a short conventional prefix, as in the existing history:
  `feat(policy): ...`, `fix(proxy): ...`, `docs: ...`, `build(release): ...`,
  `test(e2e): ...`, `chore: ...`. The release notes are grouped by these
  prefixes, so use `feat` and `fix` for anything a user should see.
- Documentation lives in `docs/` and is shipped inside the release archives.
  A user-visible change to configuration, a flag or a command should update
  [`docs/config.md`](docs/config.md) and, where it matters, the README.

## Pull requests

1. Open an issue first for anything larger than a bug fix so the scope can be
   agreed before the work is done.
2. Branch from `main`, keep the change focused and add tests for the behaviour
   you change.
3. Run `make fmt vet lint test` and, when relevant, `make e2e` and `make docs`.
4. Fill in the pull request template. Note anything that changes what the
   proxy lets through or writes to the audit log; those are the parts reviewers
   read most carefully.

## Releases

Releases are cut by the maintainer: pushing a `v*` tag, or running the
`release` workflow from the Actions tab, builds the binaries with goreleaser,
publishes them on the releases page and commits the Homebrew cask into
`Casks/`. Nothing in a pull request needs to touch that directory.

## Reporting security issues

Please do not open a public issue for a vulnerability. See
[SECURITY.md](SECURITY.md).

## License

By contributing you agree that your contributions are licensed under the
GPL-3.0-or-later, the same license as the project. See [LICENSE](LICENSE).
