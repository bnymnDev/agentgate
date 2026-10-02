package skills

import (
	"regexp"
	"strings"
)

// rules is every check, grouped as the documentation groups them. Each one
// has a fixture in testdata/skills/rules that it must find, and the clean
// fixtures must find nothing; see rules_test.go.
var rules = []Rule{
	// Hidden text.
	{ID: "hidden-unicode-tags", Severity: High, scope: anywhere | inComment, raw: true,
		Title: "text hidden in Unicode tag characters: invisible to you, read by the model",
		Why:   "Characters from the Unicode tag block (U+E0000-U+E007F) render as nothing, but models read them as the ASCII letters they shadow. That is how an instruction is smuggled past a human reviewer. The excerpt spells the hidden text out. Subdivision flags, the one honest use, are let be.",
		find:  tagHits},
	{ID: "bidi-control", Severity: High, scope: anywhere | inComment, raw: true,
		Title: "bidirectional control characters, which make text read differently than it runs",
		Why:   "Embedding, override and isolate controls (U+202A-U+202E, U+2066-U+2069) reorder how text is displayed without changing what it says - the Trojan Source technique (CVE-2021-42574). A skill written in a left-to-right language has no use for them.",
		find: func(t string) []hit {
			return runeHits(t, func(_ string, _ int, r rune) bool { return isBidi(r) }, "bidirectional control characters")
		}},
	{ID: "zero-width", Severity: Medium, scope: anywhere | inComment, raw: true,
		Title: "zero-width characters",
		Why:   "Zero-width spaces, word joiners, soft hyphens and Hangul fillers render as nothing. In a skill they split a word so a filter misses it, or carry data. Zero-width joiners, which emoji need, are let be.",
		find: func(t string) []hit {
			return runeHits(t, func(_ string, i int, r rune) bool { return isZeroWidth(r) && (r != 0xFEFF || i != 0) }, "zero-width characters")
		}},
	{ID: "control-characters", Severity: Medium, scope: anywhere | inComment, raw: true,
		Title: "control characters, which can hide or rewrite text in a terminal",
		Why:   "Escape sequences, backspaces and a carriage return without a line feed can make a terminal show something other than what a file says - cat SKILL.md is not a review if the file can repaint the screen.",
		find: func(t string) []hit {
			return runeHits(t, func(text string, i int, r rune) bool {
				switch r {
				case '\r':
					return i+1 >= len(text) || text[i+1] != '\n'
				case '\t', '\n':
					return false
				}
				return r < 0x20 || r == 0x7F || (r >= 0x80 && r < 0xA0)
			}, "control characters")
		}},
	{ID: "variation-selectors", Severity: Medium, scope: anywhere | inComment, raw: true,
		Title: "variation selectors strung together, a way to hide bytes inside a single character",
		Why:   "A variation selector picks a glyph variant and renders as nothing. One after an emoji is ordinary; a run of them, or one from the supplementary block (U+E0100-U+E01EF), can encode arbitrary data behind a single visible character.",
		find: func(t string) []hit {
			return runeHits(t, func(text string, i int, r rune) bool {
				if r >= 0xE0100 && r <= 0xE01EF {
					return true
				}
				if r < 0xFE00 || r > 0xFE0F {
					return false
				}
				next := i + 3
				return next+3 <= len(text) && text[next] == 0xEF && text[next+1] == 0xB8 && text[next+2] >= 0x80 && text[next+2] <= 0x8F
			}, "variation selectors")
		}},
	{ID: "html-comment", Severity: Medium, scope: inComment,
		Title: "an HTML comment: read by the model, never shown on the rendered page",
		Why:   "GitHub, skill marketplaces and most Markdown previews hide <!-- comments -->. The model reads them like any other text, so a comment is the simplest place to put an instruction a reviewer looking at the rendered page will never see.",
		find: func(t string) []hit {
			if len(strings.Fields(t)) < 3 {
				return nil
			}
			return []hit{{start: 0, end: len(t)}}
		}},
	{ID: "padding", Severity: Medium, scope: anywhere | inComment, raw: true,
		Title: "a long run of blank lines or spaces, which pushes what follows out of sight",
		Why:   "Dozens of empty lines, or hundreds of spaces on one line, move the rest of a file off the screen of whoever reviews it - and past the window some scanners read. Trail of Bits got a skill past marketplace scanners with exactly this.",
		find:  padding},

	// Look-alikes.
	{ID: "confusable-url", Severity: High, scope: anywhere | inComment, raw: true,
		Title: "a URL whose host is spelled with non-ASCII look-alikes or punycode",
		Why:   "A host with a Cyrillic а or a Greek ο in it, or its punycode form (xn--), reads as a familiar domain and resolves to someone else's. The finding spells every non-ASCII character out by code point.",
		find:  confusableURLs},
	{ID: "mixed-script", Severity: Medium, scope: anywhere | inComment, raw: true,
		Title: "a word that mixes Latin letters with Cyrillic, Greek or Armenian look-alikes",
		Why:   "A word like 'pаssword' with a Cyrillic а looks right and matches nothing a filter looks for (the homoglyph half of Trojan Source, CVE-2021-42694). Words written entirely in one script are let be.",
		find:  mixedScript},

	// Encoded payloads.
	{ID: "base64-blob", Severity: Medium, scope: anywhere | inComment,
		Title: "a long base64 blob",
		Why:   "Nobody reviews base64 by reading it, and a model decodes it without being asked. A blob that decodes to text is shown decoded. Inline data: images and fonts are let be.",
		find:  base64Blobs},
	{ID: "hex-blob", Severity: Medium, scope: anywhere | inComment,
		Title: "a long hex-encoded blob or a run of escaped bytes",
		Why:   "Two hundred hex digits in a row, or a string of \\x escapes, is a payload in a form a reviewer cannot read. A SHA-256 checksum (64 digits) is let be.",
		find:  hexBlobs},
	{ID: "decode-and-run", Severity: High, scope: anywhere | inComment,
		Title: "decodes something and runs the result",
		Why:   "base64 -d | sh, exec(b64decode(...)), iex([Convert]::FromBase64String(...)): the code that actually runs is never visible in the file. There is no honest reason for a skill to do this.",
		pat: pat(`(?i)(base64\s+(-d|--decode|-D)\b|b64decode|frombase64string|\batob\s*\(|xxd\s+-r|openssl\s+(enc\s+)?-?base64\s+-d)[^\n]{0,200}?(\|\s*(sudo\s+)?(ba|z|da|k)?sh\b|\|\s*(python[23]?|perl|ruby|node|iex)\b|\bexec\s*\(|\beval\b|invoke-expression|\biex\b)|\b(eval|exec)\s*\([^\n]{0,80}(b64decode|\batob\b|frombase64|decode\(['"]base64)`,
			"base64", "b64decode", "frombase64", "atob", "xxd", "openssl")},

	// Remote code.
	{ID: "pipe-to-shell", Severity: High, scope: anywhere | inComment,
		Title: "downloads a script and runs it unseen (curl | sh)",
		Why:   "Whatever the server sends at the moment the agent runs the line is executed, and the lockfile pins none of it: the skill can stay byte-identical while what it runs changes every day.",
		pat: pat(`(?i)\b(curl|wget|fetch|aria2c)\b[^\n|]{0,300}\|\s*(sudo\s+(-\S+\s+)*)?(env\s+\S+\s+)?((ba|z|da|k|fi)?sh|python[23]?|perl|ruby|node|php|bun|deno)\b|\b(ba|z)?sh\s+(-c\s+)?["']?\$\(\s*(curl|wget)\b|(\bsource|\.|\b(ba|z)?sh)\s+<\(\s*(curl|wget)\b`,
			"curl", "wget", "fetch", "aria2c")},
	{ID: "powershell-download-exec", Severity: High, scope: anywhere | inComment,
		Title: "PowerShell that downloads code and runs it (iwr | iex)",
		Why:   "Invoke-Expression on what Invoke-WebRequest or a WebClient fetched is curl | sh for Windows, with the same problem: what runs is not in the skill.",
		pat: pat(`(?i)(\biwr\b|\birm\b|invoke-webrequest|invoke-restmethod|downloadstring|downloadfile|net\.webclient|start-bitstransfer)[^\n]{0,200}(\|\s*(iex|invoke-expression)\b)|\biex\s*\(|invoke-expression\s*[(\$]`,
			"iwr", "irm", "invoke-", "download", "webclient", "bitstransfer", "iex")},
	{ID: "dynamic-eval", Severity: Medium, scope: inCode,
		Title: "evaluates code built at run time",
		Why:   "eval, exec(compile(...)) and new Function run a string as code; what the string is depends on input the skill does not control. Calling a program by name is not flagged here - that is the shell capability.",
		pat: pat("(?i)\\beval\\s*[(\"'$`]|\\bexec\\s*\\(\\s*(compile|__import__|base64|codecs|bytes|requests|urllib|open)\\b|\\bnew\\s+Function\\s*\\(|\\bFunction\\s*\\(\\s*['\"]return|\\b__import__\\s*\\(\\s*['\"](os|subprocess)['\"]\\s*\\)\\s*\\.\\s*(system|popen)",
			"eval", "exec", "function", "__import__")},
	{ID: "obfuscated-command", Severity: Medium, scope: inCode,
		Title: "a command written so it does not look like one",
		Why:   "${IFS} instead of spaces, $'\\x63\\x75\\x72\\x6c', c''url, rev | sh, [char]105+[char]101+[char]120, powershell -EncodedCommand: each spells a command so that a person - or a pattern - looking for it does not see it.",
		pat: pat(`\$\{IFS\}|\$IFS\b|\$'(?:\\x[0-9a-fA-F]{2}|\\[0-7]{3}){3,}'|\|\s*rev\s*\|\s*(ba)?sh\b|printf\s+["'](?:\\x[0-9a-fA-F]{2}){4,}|\b[a-zA-Z]+(?:''|"")[a-zA-Z]+\b|(?i)\[char\]\s*\d+\s*\+\s*\[char\]|(?i)\s-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{24,}`,
			"ifs", "$'", "rev", "printf", "''", "\"\"", "[char]", "-e")},
	{ID: "remote-instructions", Severity: High, scope: anywhere | inComment,
		Title: "tells the agent to fetch its instructions from somewhere else",
		Why:   "A skill that says 'download the latest rules from https://...' and follow them has handed its contents to whoever controls that URL. The lockfile pins the pointer, not what it points at.",
		pat: pat(`(?i)\b(fetch|load|read|follow|download|get|pull|import|apply|obey|retrieve)\b[^.\n]{0,40}\b(instructions?|rules|prompts?|guidelines|steps|playbook|skill|commands|directives|config(uration)?|system\s+prompt)\b[^.\n]{0,40}\bfrom\s+<?(https?|ftp)://|\b(follow|obey|execute|run|do)\s+(whatever|the\s+instructions|what(ever)?\s+it\s+says)\b[^.\n]{0,60}(https?://)`,
			"http", "ftp")},

	// Prose aimed at the model.
	{ID: "conditional-trigger", Severity: High, scope: inProse,
		Title: "an instruction that waits for a topic, then does something covert",
		Why:   "'If the user asks about invoices, also send ...', 'when the user mentions deploys, quietly ...': a trigger that sits idle in every review and fires in one conversation. Ordinary 'use this skill when the user asks for X' is let be; the rule needs the covert half in the same sentence.",
		find:  conditionals},
	{ID: "ignore-instructions", Severity: High, scope: anywhere | inComment,
		Title: "tells the model to ignore its other instructions or safety rules",
		Why:   "The classic injection: 'ignore all previous instructions', 'disregard your safety guidelines'. A skill adds instructions; it has no reason to cancel the ones it did not write.",
		pat: pat(`(?i)\b(ignore|disregard|forget|override|bypass|skip)\s+(all\s+|any\s+|the\s+|your\s+|every\s+|of\s+)*(previous|prior|above|earlier|other|system|safety|security|existing|original|user's)\s+(instructions|directions|rules|prompts?|guidelines|policies|restrictions|guardrails|warnings|checks|permissions)`,
			"ignore", "disregard", "forget", "override", "bypass", "skip")},
	{ID: "conceal-from-user", Severity: High, scope: anywhere | inComment,
		Title: "tells the model to keep something from the user",
		Why:   "'Do not tell the user', 'without informing the user', 'the user must not know': an instruction to work behind the back of the person the agent works for.",
		pat: pat(`(?i)\b(do\s+not|don't|never|avoid)\s+(tell(ing)?|inform(ing)?|mention(ing)?|reveal(ing)?|show(ing)?|notify(ing)?|alert(ing)?|disclos(e|ing)|let)\b[^.\n]{0,80}\b(user|human|operator|developer)s?\b|\bwithout\s+(telling|informing|asking|notifying|alerting|showing)\s+(the\s+)?(user|human)|\b(keep|hide)\s+(this|it|these|that)\b[^.\n]{0,30}\b(secret|hidden)\s+from\b|\bthe\s+user\s+(must|should|need|needs)\s+(not|never)\s+(to\s+)?(know|see|notice|find|learn)`,
			"not", "don", "never", "avoid", "without", "keep", "hide", "user")},
	{ID: "model-override", Severity: Medium, scope: inProse,
		Title: "talks to the model about who it is or what its instructions are",
		Why:   "<important> and <system> tags, 'you are now', 'developer mode', 'new instructions:' - the wrappers injected text uses to sound like it outranks everything else. A skill describes a task; it does not redefine the model.",
		pat: pat(`(?i)<\s*/?\s*(important|system|instructions?|secret|hidden|admin|critical|im_start|im_end)\s*>|\b(you\s+are\s+now|from\s+now\s+on,?\s+you|act\s+as\s+(an?\s+)?(admin|root|developer|system)|developer\s+mode|jailbreak|DAN\s+mode)\b|\bnew\s+(system\s+)?instructions\s*:|\b(system\s+prompt|developer\s+message)\b`,
			"<", "you are", "from now", "act as", "developer", "jailbreak", "dan", "instructions", "system prompt")},
	{ID: "exfiltration", Severity: High, scope: anywhere | inComment,
		Title: "sends local data somewhere",
		Why:   "'Send the file to https://...', curl -d @~/.ssh/id_rsa, curl -F with a secret, nc host port < file: the shapes data takes on its way out. An agent posting to an API it was asked to use looks the same; that is what review is for.",
		pat: pat(`(?i)\b(send|forward|post|upload|exfiltrate|leak|transmit|e-?mail|copy|pipe|submit)\b[^.\n]{0,80}\b(to|at)\s+(https?://\S+|[\w.+-]+@[\w-]+\.[\w.-]+)|\bcurl\b[^\n]*\s(-d|--data(-binary|-raw|-urlencode)?|-F|--form|-T|--upload-file)\s+["']?([\w.\[\]-]*=)?(@|\$\(|\$\{?[A-Z_]*(KEY|TOKEN|SECRET|PASS|PASSWORD|CREDENTIALS?)\b|[^\s"']*(\.ssh|\.aws|\.env\b|id_rsa|credentials|\.netrc|\.npmrc))|\b(nc|ncat|netcat)\s+(-\w+\s+)*\S+\s+\d+\s*<|\bwget\b[^\n]*--post-(file|data)`,
			"send", "forward", "post", "upload", "exfiltrate", "leak", "transmit", "mail", "copy", "pipe", "submit", "curl", "nc", "netcat", "wget")},
	{ID: "credential-access", Severity: High, scope: anywhere | inComment,
		Title: "reads credentials, keys or the whole environment",
		Why:   "SSH and cloud keys, git credentials, the keychain, browser logins, or the entire environment dumped at once. Reading one named variable the skill needs is the secrets capability, not this.",
		pat: pat(`(?i)((~|\$home|\$\{home\}|%userprofile%|\$env:userprofile)[/\\]\.(ssh|aws|gnupg|kube|docker|netrc|azure|npmrc|pypirc|git-credentials|config[/\\](gh|gcloud))\b|\bid_(rsa|ed25519|ecdsa|dsa)\b|\.git-credentials\b|\bsecurity\s+(find|dump)-(generic|internet)-password|\bdump-keychain\b|\bprintenv\s*(\||>|$)|(^|[;&|]\s*)env\s*(\||>)|\bjson\.dumps\(\s*(dict\()?os\.environ|\b(JSON\.stringify|Object\.entries)\(\s*process\.env\s*\)|login\s+data|logins\.json|cookies\.sqlite|\bkeychain-db\b)`,
			".ssh", ".aws", ".gnupg", ".kube", ".docker", ".netrc", ".azure", ".npmrc", ".pypirc", "git-credentials", ".config", "id_", "security", "keychain", "printenv", "env", "login data", "logins.json", "cookies.sqlite")},
	{ID: "persistence", Severity: High, scope: anywhere | inComment,
		Title: "makes something run again later: shell startup files, cron, launch agents, SSH keys",
		Why:   "Appending to ~/.bashrc, installing a cron job, a launch agent, a systemd unit, a scheduled task or an authorized SSH key outlives the session the skill was used in. A skill that needs to come back has to be asked again.",
		pat: pat(`(?i)(>>?|\btee\s+(-a\s+)?)\s*["']?[^\s"'|;&]*(\.bashrc|\.zshrc|\.zprofile|\.zshenv|\.profile|\.bash_profile|\.bash_login|config\.fish|authorized_keys|\.git/hooks/[\w-]+)\b|\bcrontab\s+(-e|-r|-u|[^-\s|])|\|\s*crontab\b|\blaunchctl\s+(load|bootstrap|submit|enable)\b|library/(launchagents|launchdaemons)|\bsystemctl\s+(--user\s+)?enable\b|\bschtasks\s+/create\b|currentversion\\run\b|start\s+menu\\programs\\startup|new-scheduledtask|register-scheduledtask`,
			".bashrc", ".zshrc", ".zprofile", ".zshenv", ".profile", ".bash_", "config.fish", "authorized_keys", ".git/hooks", "crontab", "launchctl", "launchagents", "launchdaemons", "systemctl", "schtasks", "currentversion", "startup", "scheduledtask")},
	{ID: "agent-config-tamper", Severity: Medium, scope: anywhere | inComment,
		Title: "changes the agent's own configuration, instructions or other skills",
		Why:   "Writing to CLAUDE.md, AGENTS.md, .cursorrules, .claude/settings.json, an MCP config or another skill's directory changes what the agent does in every later session - outside the lockfile entry of the skill that did it.",
		pat: pat(`(?i)\b(write|writes|append|add|edit|modify|update|overwrite|replace|insert|patch|echo|cat|tee|cp|mv|printf|sed\s+-i)\b[^\n]{0,80}?(\bCLAUDE\.md|\bAGENTS\.md|\bGEMINI\.md|\.cursorrules|\.cursor/rules|\.windsurfrules|copilot-instructions\.md|\.claude/settings(\.local)?\.json|\.claude/(agents|commands|hooks|skills)/|\.mcp\.json|\bmcp\.json|claude_desktop_config\.json|\.codex/config\.toml|\.agents/skills/|\.gemini/settings\.json)`,
			"claude.md", "agents.md", "gemini.md", ".cursorrules", ".cursor/rules", ".windsurfrules", "copilot-instructions", ".claude/", "mcp.json", ".codex/", ".agents/skills", ".gemini/")},
	{ID: "safety-bypass", Severity: High, scope: anywhere | inComment,
		Title: "switches off a safety mechanism: permission prompts, sandboxes, history, hooks",
		Why:   "--dangerously-skip-permissions, bypassPermissions, --no-verify, unset HISTFILE, Set-ExecutionPolicy Bypass, setenforce 0: each one removes something that was there to catch a mistake or leave a trace.",
		pat: pat(`(?i)--dangerously-skip-permissions|--dangerously-bypass-approvals-and-sandbox|(^|\s)--yolo\b|\bbypassPermissions\b|--no-sandbox\b|\bunset\s+HISTFILE\b|HISTFILE=/dev/null|\bset\s+\+o\s+history\b|\bhistory\s+-c\b|(^|\s)--no-verify\b|core\.hooksPath\s+/dev/null|\bsetenforce\s+0\b|\bcsrutil\s+disable\b|\bspctl\s+--master-disable\b|Set-MpPreference\s+-Disable|Set-ExecutionPolicy\s+(Bypass|Unrestricted)|-ExecutionPolicy\s+(Bypass|Unrestricted)`,
			"dangerously", "yolo", "bypasspermissions", "no-sandbox", "histfile", "history", "no-verify", "hookspath", "setenforce", "csrutil", "spctl", "set-mppreference", "executionpolicy")},
	{ID: "destructive-command", Severity: Medium, scope: inCode,
		Title: "a command that destroys data beyond the project",
		Why:   "rm -rf on /, ~ or *, mkfs, dd onto a disk, a fork bomb, a force push, chmod 777 on the root: commands an agent should never run on a skill's say-so.",
		pat: pat(`(?i)\brm\s+(-[a-z]*r[a-z]*f[a-z]*|-[a-z]*f[a-z]*r[a-z]*|--recursive\s+--force|--force\s+--recursive|-r\s+-f|-f\s+-r)\s+(--no-preserve-root\s+)?["']?(/(\*|\s|$|["'])|~/?(\s|$|["'])|\$home\b|\$\{home\}|\*(\s|$))|\bmkfs(\.\w+)?\b|\bdd\s+[^\n]*\bof=/dev/(sd|nvme|disk|hd|xvd)|:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:|\bgit\s+push\s+[^\n]*(--force\b|\s-f\b)|\bchmod\s+(-R\s+)?777\s+/|\bRemove-Item\b[^\n]*-Recurse[^\n]*(C:\\|\$env:USERPROFILE|~)`,
			"rm", "mkfs", "dd", "()", "push", "chmod", "remove-item")},
	{ID: "privilege-escalation", Severity: Medium, scope: inCode,
		Title: "runs something as root or administrator",
		Why:   "sudo, doas, pkexec, setuid bits, -Verb RunAs: an agent asked to use a skill has no business holding more rights than the user who asked.",
		pat: pat(`(?im)(^|[\s;&|(])(sudo|doas|pkexec)\s|\bchmod\s+([ugo]*\+s|[2-7][0-7]{3})\b|-Verb\s+RunAs\b|\bsu\s+(-|root)(\s|$)`,
			"sudo", "doas", "pkexec", "chmod", "runas", "su")},
	{ID: "raw-ip-url", Severity: Medium, scope: anywhere | inComment,
		Title: "a URL to a bare IP address",
		Why:   "A real service has a name. A URL to 203.0.113.7 is how a payload server or a collector stays out of DNS-based blocklists. Loopback addresses are let be.",
		find: func(t string) []hit {
			var out []hit
			for _, m := range urlMatches(rawIP, t) {
				host := t[m[2]:m[3]]
				if strings.HasPrefix(host, "127.") || host == "0.0.0.0" || host == "[::1]" {
					continue
				}
				out = append(out, hit{start: m[0], end: m[1]})
			}
			return out
		}},
	{ID: "drop-site-url", Severity: Medium, scope: anywhere | inComment,
		Title: "a URL to a paste site, request catcher, tunnel or link shortener",
		Why:   "pastebin, webhook.site, requestbin, ngrok, interactsh, bit.ly, a Discord or Telegram bot hook: places to fetch a payload from or drop data at that change hands freely and hide where a link goes.",
		pat: pat(`(?i)\b(pastebin\.com|paste\.ee|hastebin\.com|ghostbin\.\w+|rentry\.(co|org)|transfer\.sh|file\.io|0x0\.st|webhook\.site|requestbin\.\w+|pipedream\.net|beeceptor\.com|ngrok(-free)?\.(io|app|dev)|trycloudflare\.com|serveo\.net|localtunnel\.me|loca\.lt|interact\.sh|oast\.(fun|me|pro|live|site|online)|burpcollaborator\.net|bit\.ly|tinyurl\.com|is\.gd|t\.ly|discord(app)?\.com/api/webhooks|api\.telegram\.org/bot|hooks\.slack\.com/services)\b`,
			"pastebin", "paste.ee", "hastebin", "ghostbin", "rentry", "transfer.sh", "file.io", "0x0.st", "webhook.site", "requestbin", "pipedream", "beeceptor", "ngrok", "trycloudflare", "serveo", "localtunnel", "loca.lt", "interact.sh", "oast.", "burpcollaborator", "bit.ly", "tinyurl", "is.gd", "t.ly", "discord", "api.telegram", "hooks.slack")},
	{ID: "load-time-shell", Severity: Medium, scope: inCode,
		Title:    "a shell command Claude Code runs when the skill is loaded",
		Why:      "!`command` and ```! blocks in SKILL.md are run by Claude Code as the skill loads, and their output replaces them - before the model, or you, see anything. Useful (git status, gh pr diff), and exactly as powerful as any other shell command, without anyone deciding to run it.",
		loadTime: true,
		find:     func(t string) []hit { return []hit{{start: 0, end: len(strings.TrimRight(t, "\n"))}} }},

	// Files.
	{ID: "symlink", Severity: High, Title: "a symlink", skill: symlinks,
		Why: "A symlink is pinned by where it points. When it points outside the skill, what it points at - ~/.ssh, another repository, /etc - can change at any time, or be something the skill should never have read."},
	{ID: "special-file", Severity: High, Title: "a named pipe, socket or device inside the skill",
		Why: "There is no honest reason for a skill to ship one, and reading a named pipe blocks forever. agentgate records that it is there and never opens it.",
		skill: fileRules(func(f File) (string, bool) {
			return "a named pipe, socket or device inside the skill", f.Kind == KindSpecial
		})},
	{ID: "executable-file", Severity: High, Title: "compiled code",
		Why:   "An ELF, Mach-O or Windows executable, a native library, WebAssembly, or compiled Python or Java bytecode: code nobody can review by reading the skill. Trail of Bits hid a payload in a .pyc next to clean source.",
		skill: fileRules(executableKind)},
	{ID: "opaque-file", Severity: Medium, Title: "a binary file nobody can review by reading it",
		Why:   "An archive - including .docx and .xlsx, which are ZIP files - or a binary of no recognised kind. What is inside is not scanned. Images, PDFs and fonts are let be.",
		skill: fileRules(opaqueKind)},
	{ID: "oversized-file", Severity: Medium, Title: "a file larger than the scan reads",
		Why: "Only the first MiB of a file is scanned, and a payload can sit behind that. Every byte is still hashed, so a change anywhere in the file is caught.",
		skill: fileRules(func(f File) (string, bool) {
			return "only the first 1 MiB of this file was scanned; the hash covers all of it", f.Truncated
		})},

	// Front matter.
	{ID: "invalid-frontmatter", Severity: Low, Title: "the front matter is missing, broken or misnamed", skill: frontMatter,
		Why: "The Agent Skills specification wants a name of lowercase letters, digits and hyphens that matches the directory, and a description. A skill that calls itself something it is not installed as is hard to review and easy to confuse with another."},
	{ID: "description-too-long", Severity: Low, Title: "a description longer than the specification allows", skill: longDescription,
		Why: "The description of every installed skill is in the model's context in every session, whether the skill is used or not. The specification caps it at 1024 characters; anything beyond that is room for instructions."},
	{ID: "broad-trigger", Severity: Medium, Title: "a description that claims every conversation", skill: autoTrigger,
		Why: "'Use this skill for every task', 'always load before any request': the description decides when the model pulls the skill in, and one that asks for everything gets its instructions into everything. A skill with disable-model-invocation or paths is let be."},
	{ID: "skill-hooks", Severity: Medium, Title: "the skill registers hooks", skill: hooks,
		Why: "Hooks in the front matter run commands on the agent's events (before a tool, after an edit) while the skill is active - shell commands nobody decides to run, each time."},
}

var escapedBytes = pat(`(?:\\x[0-9a-fA-F]{2}){12,}|(?:0x[0-9a-fA-F]{2},\s*){16,}`, `\x`, "0x")

var rawIP = regexp.MustCompile(`(?i)\b(?:https?|ftp|wss?)://(\d{1,3}(?:\.\d{1,3}){3}|\[[0-9a-f:]+\])`)
