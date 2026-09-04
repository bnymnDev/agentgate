# What else could you do instead?

## Run the MCP servers raw

The default. It is fine right up until it is not.

| | Raw | agentgate |
|---|---|---|
| Setup | none | one config file, one line changed in the host |
| Blocking a dangerous call | not possible | a rule |
| Knowing what the agent did | scroll the host's UI, if it shows tool calls at all | a queryable local database |
| Knowing what it did *last week* | no | `agentgate sessions --since 7d` |
| Testing a change to your guardrails | there are none to change | `replay --dry-run` against a real session |
| Overhead | none | one process, one extra hop, microseconds per call |

Running raw is the right choice for a server that only reads. It stops being the
right choice the first time a server can write, spend or deploy.

## Wrap each server in a shell script

The usual next step: a script that inspects `argv`, refuses some things and
`exec`s the real server.

It works, and it has four problems.

1. **It is per server.** Ten servers, ten scripts, ten sets of subtly different
   rules.
2. **It cannot see the call.** MCP arguments arrive as JSON-RPC on stdin, not as
   `argv`. A wrapper that does not speak MCP can gate *whether the server runs*,
   not *what it is asked to do*. Gating a single tool call means parsing the
   protocol — at which point you have written half of agentgate.
3. **It has no memory.** No record of what was allowed, so nothing to review and
   nothing to test a change against.
4. **Denial looks like a crash.** A wrapper that exits kills the connection. The
   agent sees a transport failure and usually retries the same thing. agentgate
   returns a *tool result* saying why, and the agent adapts.

## Use the host's own permission prompts

Claude Code, Cursor and others ask before running some tools, and that is
genuinely useful. It is also:

- **per host** — your rules do not follow you when you switch editors, and do not
  apply at all to an agent running in CI;
- **per session** — "allow always" is a decision you make once, in a hurry, and
  cannot review later;
- **not expressible** — "allow `stock_set` but only when `dryRun` is true" is not
  something a yes/no prompt can say;
- **not recorded** — there is no artefact afterwards.

The two compose well: let the host ask about the interactive things, and let
agentgate enforce the invariants that should hold whether or not anyone is
watching.

## Write an MCP server that proxies the others

That is what agentgate is. If you only need it for one server and one rule,
fifty lines of the Go or TypeScript SDK will do it, and you should write them.

What you get by not writing them: the policy language, the audit store with
redaction and retention, replay and diff, the approvals flow, the web UI,
multi-upstream merging with prefixing, and the passthrough tests that keep the
transparent path honest.

## Sandbox the whole thing — containers, seccomp, a VM

A different layer, solving a different problem, and worth doing as well.

A sandbox constrains what a *process* can touch. It cannot tell a legitimate
`POST /orders` from a wrong one, because at that layer both are a socket write.
agentgate constrains what a *tool call* can be, and knows the difference between
`dryRun: true` and `dryRun: false`.

Sandbox for the blast radius. agentgate for the semantics, and for the record.

## Where agentgate is the wrong tool

- **You want a model to judge whether a call is safe.** Explicitly a non-goal.
  Rules here are deterministic, and the reason for that is `replay`: a decision
  you cannot reproduce is a decision you cannot test.
- **You want central policy for a team.** v0.1 is local, single-user, single
  file. No server, no sync, no accounts.
- **You want to govern prompts, sampling or resources.** v0.1 governs tools;
  everything else passes through.
- **You need an authenticated, internet-facing dashboard.** The UI is localhost
  by design and refuses to bind elsewhere without an explicit flag.
