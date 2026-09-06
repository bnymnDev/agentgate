## What

<!-- One or two sentences: what changes and why. Link the issue if there is one. -->

## How

<!-- Anything a reviewer should know about the approach or the trade-offs. -->

## Effect on enforcement and the audit log

<!-- Does this change what the proxy lets through, denies, asks about or records?
     If so, describe it; if not, say "none". -->

## Checklist

- [ ] `make fmt vet lint test` passes
- [ ] `make e2e` passes, if the proxy, CLI or audit store changed
- [ ] `make golden` was run and the diff reviewed, if policy evaluation changed
- [ ] `make docs` was run, if a command, flag, matcher or redaction pattern changed
- [ ] `docs/` and the README reflect any user-visible change
