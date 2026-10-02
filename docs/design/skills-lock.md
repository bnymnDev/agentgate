# Design: a lockfile for Agent Skills

Status: implemented on `feature/skills-lock` (not released). User
documentation: [docs/skills.md](../skills.md).

This document records why the feature exists, what it was asked to be, what
was built, where and why it differs from the brief, and how it stands against
the acceptance criteria.

## Problem

Agent Skills — a directory with a `SKILL.md` (YAML front matter plus
instructions) and optional `scripts/`, `references/` and `assets/` — have
become the fastest-growing way to extend coding agents. They are a supply
chain in which the payload is prose read by a model:

- Skills are loaded from the project (`.claude/skills`, `.agents/skills`),
  the user's home directory, plugins and marketplaces, and change whenever
  any of those is updated. No agent records what it loaded last time.
- Instructions can be hidden from a human reviewer (Unicode tag characters,
  HTML comments, padding) while remaining fully visible to the model.
- Scripts and code blocks can fetch and run code that is not in the skill.

agentgate already pins MCP tool definitions in a lockfile and scans them for
poisoning (`internal/pinning`). Skills are the same problem one layer over:
instructions the model follows, supplied by a third party, that can change
silently.

## Research

Checked on 2026-10-02. Figures are quoted as the sources state them; where a
claim in the original brief did not hold up, the correction is noted.

| Source | What it supports |
|---|---|
| Yang, Fu, Tantithamthavorn, Arora, Chua: *Towards a Risk Assessment of Malicious Skill Files in Coding Agents*, [arXiv:2608.05223](https://arxiv.org/abs/2608.05223) (Aug 2026) | A benchmark of 2,826 adversarial skill files mapped to 11 MITRE ATT&CK tactics; Gemini CLI was exploited in 95.5–96.1 % of runs, Qwen Code in 71.6–74.0 %; models recognised the risk in about 2 % of runs. *(The brief said "95.5 %"; the paper gives a range.)* |
| Snyk, [ToxicSkills](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub) (Feb 2026) | 3,984 skills from ClawHub and skills.sh scanned: 13.4 % with critical flaws, 36.8 % with at least one, 76 confirmed malicious payloads, 91 % of malicious skills combine malware with prompt injection. |
| Koi Security, [ClawHavoc](https://koi.ai/blog/clawhavoc-341-malicious-clawedbot-skills-found-by-the-bot-they-were-targeting) | The source of the "824 malicious skills on ClawHub" figure in the brief (341 at first, 824 by 16 Feb 2026). *Not on the Snyk page the brief attributed it to; seen in search summaries, not re-read in full — treat as reported, not verified.* |
| Trail of Bits, [The Sorry State of Skill Distribution](https://blog.trailofbits.com/2026/06/03/the-sorry-state-of-skill-distribution/) (Jun 2026) | Bypassed ClawHub's detector, Cisco's scanner and the scanners built into skills.sh; three bypasses took under an hour, the fourth (against an LLM guard) hours. Techniques: 100,000 lines of padding, payloads in `.docx` archives and `.pyc` bytecode, persuasive text aimed at the guard model. *(The brief said "all scanners in under an hour"; it was three of four.)* These techniques became the `padding`, `opaque-file` and `executable-file` rules, and the decision not to use a model. |
| CSA, [Agent Context Poisoning: SKILL.md and the New AI Supply Chain Attack Surface](https://labs.cloudsecurityalliance.org/research/csa-research-note-skill-md-agent-context-poisoning-20260506/) (May 2026) | Recommends content-hash verification before loading skills, content signing, and filtering Unicode tag characters. |
| OWASP [Agentic Skills Top 10, AST01](https://owasp.github.io/www-project-agentic-skills-top-10/ast01) | Recommends signed skills (ed25519), Merkle-root signing for registries and hash-pinning installed skills with alerts on change; notes that signatures prove authorship, not safety. |
| Snyk/unite.ai, [Emerging Supply Chain Risks in Skills Marketplaces](https://www.unite.ai/ai-agent-skills-supply-chain-security-vulnerabilities/) (Jun 2026) | "Roughly 1 in 8" skills with a critical flaw; no mandatory signing, review or sandboxing in marketplaces. |
| [gittrend.io, September 2026](https://gittrend.io/monthly/2026-09) | Skills repositories among the fastest-growing on GitHub: archify at 75.8k stars total (+36.3k in September; the brief's "75.7k" was slightly off), mattpocock/skills +30.1k in the month. |
| [liyixuan201211/skillnotary](https://github.com/liyixuan201211/skillnotary) | Closest prior art: a Node tool that writes a `skills.lock` of SHA-256 digests and declared capabilities, detects capability drift and signs DSSE/in-toto attestations. Very early (one star at the time of writing). agentgate differs in deriving capabilities from content instead of declarations, in the prose diff, and in the rules. |
| [Agent Skills specification](https://agentskills.io/specification) | `name` 1–64 lowercase letters, digits and hyphens, matching the directory; `description` 1–1024 characters; optional `allowed-tools`, `license`, `compatibility`, `metadata`. |
| [Claude Code skills docs](https://code.claude.com/docs/en/skills) | Locations (personal, project, nested, plugin, enterprise); front matter fields including `allowed-tools`, `hooks`, `disable-model-invocation`, `paths`; `` !`command` `` and ` ```! ` blocks that run as the skill loads. |
| [Codex skills docs](https://learn.chatgpt.com/docs/build-skills) | `.agents/skills` from the working directory up to the repository root, `$HOME/.agents/skills`, `/etc/codex/skills`. *The brief's `~/.codex/skills` is not in the current docs; it is still searched as a legacy location.* |
| Rehberger, [ASCII Smuggler](https://embracethered.com/blog/posts/2024/hiding-and-finding-text-with-unicode-tags/) (Embrace The Red, 2024) | Unicode tag characters are invisible in most interfaces and read by models. |
| Boucher, Anderson, [Trojan Source](https://trojansource.codes/) | Bidi overrides (CVE-2021-42574) and homoglyphs (CVE-2021-42694). |
| [RFC 6962 §2.1](https://www.rfc-editor.org/rfc/rfc6962#section-2.1) | The Merkle tree shape used for the root. |

Assessment, not sourced: hiding data in runs of Unicode variation selectors
is a publicly discussed technique (2025) and cheap to detect; the
`variation-selectors` rule is included on that basis.

## What was built

```
internal/skills/      the package
  skill.go            loading a skill: walk, hash, classify text/binary, front matter
  merkle.go           RFC 6962-shaped Merkle root over (path, kind, content hash)
  discover.go         project / user / plugin / --path roots, stable keys
  markdown.go         front matter, prose, fenced code, inline code, HTML comments
  match.go            keyword prefilter in front of regular expressions
  rules.go            finding type, scan driver, rule helpers
  ruletable.go        the 42 rules
  label.go            the 10 capability classes and their evidence
  lockfile.go         skills.lock: load, save, check, approve
  diff.go             sentence-level prose diff, imperative detection
  markdown_report.go  Markdown report, diff block, badge
internal/cli/skills.go  agentgate skills lock|verify|diff|approve|label|scan
action.yml              skills, skills-lockfile, skills-fail inputs; skills-report output
testdata/skills/        rules/ (one fixture per rule), clean/, label/, golden/, project/
e2e/skills_test.go      the real binary against prepared skill directories
```

### Commands

| Command | Does | Exit |
|---|---|---|
| `skills lock` | pins skills not in the lockfile yet, prints their label and findings | 0 |
| `skills verify` | compares everything with the lockfile; `--markdown`, `--json` | 1 on any non-`locked` skill |
| `skills diff [skill…]` | file changes, gained capabilities and hosts, unapproved findings, sentence-level diff; `--markdown` | 0 |
| `skills approve <skill…>` / `--all` | records skills as they are now, findings accepted | 0 |
| `skills label [skill…]` | capabilities with evidence; `--markdown` badge and table; `--json` | 0 |
| `skills scan <dir…>` | label and findings without a lockfile; `--fail-on` | 1 on a finding at or above the threshold |

## Decisions, and where the brief was changed

1. **A separate `skills.lock`, not an extension of `agentgate.lock`.** The tool
   lockfile lives next to `agentgate.yaml` and is maintained by a running
   proxy; skills are files in a repository, checked in CI, with no proxy
   involved. Mixing them would force a config file onto every skills user and
   tie two different lifecycles together. The conventions are shared instead:
   versioned JSON, atomic writes, accepted findings recorded per entry, the
   same `Reveal` rendering of hidden text, the scan's `VisibleText` folding
   (exported from `internal/pinning` for this).

2. **No goldmark.** The brief suggested a Markdown AST. What the rules need is
   only to tell front matter, prose, fenced code, inline code and HTML
   comments apart; a 200-line segmenter does that, and every other text file
   is read as prose *and* code anyway, so a misclassification changes the scope
   of a few rules, never whether text is read. One dependency fewer in a
   security tool is worth more than CommonMark fidelity here.

3. **Merkle tree in RFC 6962 shape** with path and kind in every leaf, so a
   rename or a symlink swap changes the root exactly like an edit. Per-file
   hashes are stored too, so a change can be traced to its file.

4. **CRLF is read as LF for text files.** Without it, a Windows checkout with
   `core.autocrlf` — the default on GitHub's Windows runners — would never
   verify. A lone `CR` still counts, and is itself a finding.

5. **`SKILL.md` is stored in the lockfile** (first 256 KiB) so `diff` can show
   what changed without git. The alternative, diffing against a git revision,
   would not work for `~/.claude/skills` or plugins, which are rarely
   repositories of the user's.

6. **Findings are accepted by content, not by line.** A finding's key is rule,
   file and a hash of what was found; moving a line does not reopen an
   accepted finding, a second instance of the same thing does.

7. **A fifth status, `rescanned`.** An agentgate upgrade that brings new rules
   can see more in an unchanged skill. Failing `verify` on that is the
   conservative choice: a newly visible capability deserves a look just as
   much as a newly written one.

8. **`scan` was added** (not in the brief): vetting a skill *before* it is
   installed is the moment a reviewer can still say no, and it needs no
   lockfile.

9. **No model, anywhere.** Trail of Bits' fourth bypass talked an LLM guard
   out of its verdict. Deterministic rules can be evaded too, but they cannot
   be persuaded, and their results replay.

10. **Performance by prefilter and parallelism.** Go's RE2 engine runs these
    alternations at a few MB/s. Each pattern carries the literal keywords
    every match contains; it runs only on the lines (plus two following) where
    a keyword occurs. Skills are checked on all cores. 200 skills of realistic
    size check in about 0.25 s on the development machine
    (`TestTwoHundredSkillsUnderASecond`).

11. **Policy integration was not built.** The policy language decides on tool
    calls at run time; a skill is not a tool call, and agentgate does not see
    which skills an agent loads. A rule like "deny when an unapproved skill
    is present" would need a file-system check inside the evaluator, which the
    design principles forbid ("evaluation is pure"). See the roadmap.

12. **The WASM web demo from the original pitch was not built.** It needs a
    hosted page outside this repository and adds nothing the `scan` command
    does not; it is on the roadmap rather than half-done.

## Roadmap

- **Signatures.** OWASP AST01 recommends ed25519-signed skills. A
  `skills approve --sign` that writes a detached signature over the lockfile
  entry, and `verify --keys` that checks it, would turn "someone approved"
  into "this key approved". Not built because key management deserves its
  own design.
- **`agentgate doctor` and `init`**: report an outdated `skills.lock` next to
  a project, and offer to create one.
- **A run-time hook**: a Claude Code `SessionStart` hook that runs
  `skills verify` and refuses to start on drift — closes the gap between the
  last CI run and the agent loading a skill.
- **Nested discovery** without `--path` globs (Claude Code loads
  `<subdir>/.claude/skills`), and Gemini CLI's skill locations once
  documented.
- **SARIF output** for GitHub code scanning.
- **The WASM page**: paste a `SKILL.md`, see the label, findings and hidden
  text — `scan` compiled to WebAssembly.

## Review

Before completion, the feature was reviewed adversarially by four reviewers —
correctness, security (evasion, symlinks, traversal, size), consistency with
the rest of agentgate, and documentation against the acceptance criteria —
each followed by a skeptic that tried to refute every finding by reproducing
it. 21 findings were confirmed, one was refuted (CRLF normalisation of shell
scripts: bash on Linux and macOS treats the `CR` as part of the command, so
the flip is a visible break rather than a silent change). All 21 were fixed,
each with a test:

| Finding | Fix |
|---|---|
| One invalid byte made `SKILL.md` "binary" and switched every text rule off | text-like files are scanned with bad bytes replaced; new rule `malformed-text` (high) |
| A fenced block inside an HTML comment was read as code, not as a hidden comment | comment blocks are recognised before fences |
| A skill whose `SKILL.md` is a symlink was not found at all | it is a skill; a symlink to a file is pinned and scanned by its target's content |
| Any `.git/` with a `HEAD`, `.DS_Store` and `Thumbs.db` were not hashed | only a real repository at the skill root is left out, with a `git-repository` finding; everything else is hashed |
| `approve <name>` matched the skill's own front-matter name, so one skill could be approved as another | matching by directory only; an ambiguous name is refused |
| `--path .` gave a machine-specific key and hashed the lockfile into the skill | key `.`; the lockfile is excluded |
| A variation selector inside a word, a curly apostrophe or a double space defeated prose rules | folded out before matching; a selector after ASCII is a `variation-selectors` finding |
| The keyword prefilter missed matches starting on the previous line | windows start one line earlier |
| `curl … \| /bin/bash`, `\| /usr/bin/env bash`, `\| tee f \| sh` were not `pipe-to-shell` | the pattern allows paths and intermediate stages |
| Paths, keys and details could carry escape sequences and newlines to the terminal | everything printed from a skill goes through `RevealLine` |
| Skill text in the Action log could issue workflow commands | the log output is wrapped in `::stop-commands::` |
| Line counting was quadratic; a file could produce millions of findings | counted once per pass; at most 50 per rule and stretch |
| A missing `--dir`, a `--path` that names nothing, or no lockfile passed `verify` | they fail; `verify --missing-ok` opts in |
| The Action reported a broken check as drift, and passed on old releases | a failed check fails the step; an old release fails it too |
| `gendocs` expanded `$` in generated text (`${IFS}` vanished) | content is inserted literally — a bug that predates this feature |
| Diff lines pointed at the paragraph, not the sentence; inline code in an added sentence was not read as code | per-sentence lines; prose and code scanned separately |
| `--lockfile` usage text had `<dir>` that GitHub strips; `lock --json` printed `null`; docs example and placeholder status | fixed |

## Status against the acceptance criteria

| | Criterion | Status | Evidence |
|---|---|---|---|
| a | `skills lock\|verify\|diff\|label\|approve` work and are documented, `make docs` without drift | ✅ | plus `scan`; [docs/skills.md](../skills.md), generated command and flag tables in README and [config.md](../config.md); CI job "docs are in sync" |
| b | Merkle root over all files; every file change caught by `verify` | ✅ | `merkle.go`; `TestMerkleRoot` (RFC 6962 shape), `TestEveryFileChangeIsCaught` (edit, add, hidden file, remove, rename, one byte), `TestSymlinksArePinnedByTargetAndContent`, `TestDirectoriesThatOnlyLookLikeGitArePinned`, `TestOversizedFileIsHashedWhole`; e2e "a one-byte change to a script fails verify" |
| c | Label derives at least 7 capability classes, golden tests | ✅ | 10 classes; `TestLabelFixtures` with goldens in `testdata/skills/golden/label`, `TestEveryCapabilityHasAFixture` |
| d | At least 25 heuristics with fixtures, Unicode tag, bidi and zero-width included | ✅ | 42 rules, each with a fixture (38 in `testdata/skills/rules`, 4 built by tests) and a golden; `TestEveryRuleHasAFixture`; false-positive guard `TestCleanFixturesFindNothing`; `TestReviewedEvasionsAreCaught` |
| e | Prose diff marks new imperatives and new capabilities, terminal and Markdown | ✅ | `diff.go`; `TestProseDiff*`, `TestImperative`; `printDetails` (terminal), `Markdown`/`MarkdownDiff`; e2e checks `[imperative, …]` and the Markdown report |
| f | `verify` exits non-zero on an unapproved change, `approve` resets (e2e) | ✅ | `TestSkillsLockVerifyApprove` in `e2e/skills_test.go` |
| g | GitHub Action can check skills, backwards compatible | ✅ | `skills`, `skills-lockfile`, `skills-fail` inputs, `skills-report` output, all off by default; CI job "GitHub Action works" runs a clean and a drifted project |
| h | `make test`, `make e2e`, `make vet`, `make lint` green; CHANGELOG under Unreleased | ✅ | `go test -race ./...`, e2e, vet and golangci-lint v2.13.2 (the version CI pins) pass locally; CI green on Linux, macOS and Windows; CHANGELOG "Unreleased → Added" |
| i | `docs/skills.md` with threat model and limits; README section | ✅ | [Threat model](../skills.md#threat-model) with "What it does not do"; README "Skill lockfile" row, recording, CI note, docs table |
| j | This design document with status | ✅ | this section |
| — | 40+ tests, `-race` green, no cgo, no new network access | ✅ | 118 passing test cases in `internal/skills`, 6 e2e cases; one new direct dependency, `golang.org/x/text` (already in the module graph) |
| — | 200 skills in under a second | ✅ | `TestTwoHundredSkillsUnderASecond`: about 0.25 s locally |
| — | Demo transcript | ✅ | `docs/demo/skills.txt` and `skills.gif`, rendered by `make demo`'s renderer from real output |
| — | Policy integration | ⚠️ | not built; why, and what would replace it, under decision 11 and the roadmap |
| — | WASM web demo (original pitch) | ❌ | out of scope for this repository; on the roadmap |
