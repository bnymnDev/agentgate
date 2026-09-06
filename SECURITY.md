# Security policy

agentgate is a security tool: it decides which tool calls an AI agent may make,
records what it did and can stop it. A flaw in agentgate can therefore let an
agent do something a policy was written to prevent. Reports are taken
seriously and answered promptly.

## Reporting a vulnerability

Please report vulnerabilities through GitHub's private vulnerability reporting
for this repository:

https://github.com/bnymnDev/agentgate/security/advisories/new

Do not open a public issue or pull request for a security problem, and do not
describe it in a public discussion until a fix has been released.

A useful report contains the agentgate version (`agentgate --version` or the
tag), the configuration that reproduces the problem with any secrets removed,
what you expected the policy to do, and what happened instead. A recorded
session or a `check` invocation that demonstrates the bypass is ideal.

You will get an acknowledgement, a fix or a mitigation, and credit in the
release notes if you want it. Please allow a reasonable time for a fix before
publishing details.

## Supported versions

Only the latest release receives security fixes. Upgrade with
`go install github.com/bnymnDev/agentgate/cmd/agentgate@latest` or through the
Homebrew cask.

## Scope

In scope, and the kind of thing we most want to hear about:

- A tool call that matches a `deny` or `ask` rule but reaches the upstream
  server anyway, including through the naming of tools, argument encoding,
  batching or any other MCP feature.
- The kill switch (`freeze`) not stopping calls, or being lifted without
  `unfreeze`.
- A honeypot tool that does not trip, or a loop guard or budget that can be
  bypassed.
- Secrets that reach the audit log or a webhook despite redaction, or reach the
  model when `redact_results` is on.
- Audit records that can be altered or suppressed by the agent or by an
  upstream server.
- The web UI binding to a non-loopback address without `--allow-remote-ui`,
  or any way to act on the gateway from another machine.
- Replay producing a different decision from the live evaluation for the same
  policy and call.

Out of scope by design; these are documented limits rather than
vulnerabilities:

- The web UI has no authentication. It is meant for localhost only, and the
  documentation says so.
- Anything a policy allows. agentgate enforces the rules you write; it does not
  judge whether they are wise.
- Prompts, resources and sampling pass through untouched. Only tool calls are
  governed.
- Denial of service by a host or upstream that agentgate is configured to trust.
- Vulnerabilities in the MCP servers behind agentgate or in the host in front
  of it. Please report those to the respective projects.

## Hardening advice

- Run agentgate with `default: deny` once you have a policy you trust; use
  shadow mode and `policy suggest` to get there.
- Keep the web UI on localhost.
- Give the process only the filesystem access it needs; the audit database
  contains everything the agent did.
