package skills

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// Capability is one class of thing a skill can make the agent do.
type Capability struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	// Why says what counts, and what does not.
	Why string `json:"why"`

	scope scope
	pat   pattern
	// skill derives the capability from the skill as a whole.
	skill func(s *Skill) []Evidence
}

// Evidence is where a capability was seen.
type Evidence struct {
	Capability string `json:"capability"`
	File       string `json:"file"`
	Line       int    `json:"line,omitempty"`
	Excerpt    string `json:"excerpt"`
}

// Where is file:line.
func (e Evidence) Where() string {
	if e.Line > 0 {
		return fmt.Sprintf("%s:%d", e.File, e.Line)
	}
	return e.File
}

// Label is what a skill can do, derived from what is in it.
type Label struct {
	// Capabilities are the IDs, sorted.
	Capabilities []string `json:"capabilities"`
	// Hosts are the hosts of every URL in the skill, sorted.
	Hosts    []string   `json:"hosts,omitempty"`
	Evidence []Evidence `json:"evidence,omitempty"`
}

// Has reports whether the label lists a capability.
func (l Label) Has(id string) bool {
	for _, c := range l.Capabilities {
		if c == id {
			return true
		}
	}
	return false
}

// Capabilities lists every capability class, in the order the label shows
// them.
func Capabilities() []Capability { return append([]Capability(nil), capabilities...) }

// CapabilityTitle is the one-line title of a capability.
func CapabilityTitle(id string) string {
	for _, c := range capabilities {
		if c.ID == id {
			return c.Title
		}
	}
	return id
}

var capabilities = []Capability{
	{ID: "shell", Title: "runs shell commands",
		Why:   "Shell code blocks, shell scripts, calls that start a process (subprocess, os.system, child_process, exec.Command), Bash among the allowed tools, and the commands Claude Code runs as the skill loads.",
		scope: inCode,
		pat: pat(`(?i)\bsubprocess\.(run|call|check_call|check_output|Popen)\b|\bos\.(system|popen|exec\w*)\s*\(|\bchild_process\b|\bexec\.Command(Context)?\s*\(|\bspawnSync?\s*\(|\bexecSync\s*\(|\bRuntime\.getRuntime\(\)\.exec|\bProcess\.Start\b|\bStart-Process\b|\bShellExecute`,
			"subprocess", "os.", "child_process", "exec.command", "spawn", "execsync", "getruntime", "process.start", "start-process", "shellexecute"),
		skill: shellEvidence},
	{ID: "scripts", Title: "ships code for the agent to run",
		Why:   "Script files in the skill - by extension or #! line - and compiled code. The agent may run them; the label says they are there.",
		skill: scriptEvidence},
	{ID: "network", Title: "talks to the network",
		Why:   "Code that downloads, uploads or connects: curl, wget, HTTP clients in Python, Node, Go and PowerShell, ssh, scp, rsync, nc, git clone and push, and WebFetch or WebSearch among the allowed tools. A link in the prose is not network access; it shows up under urls.",
		scope: inCode,
		pat: pat(`(?i)\b(curl|wget|aria2c|httpie|nc|ncat|netcat|ssh|scp|sftp|rsync|telnet|ftp)\s|\bhttps?\s+(get|post|put)\b|\b(requests|httpx|aiohttp|urllib3?)\.\w+\(|\burllib\.request\b|\bfetch\s*\(\s*["'`+"`"+`]?(https?:|\$\{|[a-z_]+\))|\baxios\b|\bhttp\.(Get|Post|NewRequest)\b|\bnet\.Dial\b|\bsocket\.(socket|create_connection)\b|Invoke-(WebRequest|RestMethod)|\b(iwr|irm)\s|Net\.WebClient|\bgit\s+(clone|fetch|pull|push|ls-remote)\b|\bgh\s+(api|pr|issue|release|repo)\b|\bnpm\s+publish\b|\bdocker\s+(pull|push)\b`,
			"curl", "wget", "aria2c", "httpie", "nc", "netcat", "ssh", "scp", "sftp", "rsync", "telnet", "ftp", "http", "requests", "httpx", "aiohttp", "urllib", "fetch", "axios", "net.dial", "socket", "invoke-", "iwr", "irm", "webclient", "git", "gh ", "npm", "docker"),
		skill: networkTools},
	{ID: "urls", Title: "points at external URLs",
		Why:   "Every host a URL in the skill names, prose and code alike. The label lists them; loopback addresses are left out.",
		skill: func(s *Skill) []Evidence { return urlEvidence(urlsIn(s)) }},
	{ID: "secrets", Title: "reads secrets or credentials",
		Why:   "Environment variables named like a key, token, secret or password, .env files, credential files and stores (~/.ssh, ~/.aws, the keychain), and code that reads the whole environment.",
		scope: anywhere,
		pat: pat(`\$\{?[A-Z][A-Z0-9_]*(KEY|TOKEN|SECRET|PASSWORD|PASSWD|PASS|CREDENTIALS?|PAT|AUTH)\b|\b(process\.env|os\.environ|os\.getenv|Getenv|System\.getenv|ENV\[)[^\n]{0,40}(KEY|TOKEN|SECRET|PASSWORD|PASS|CREDENTIAL|AUTH)|(?i)(^|[\s"'/(])\.env(\.\w+)?\b|(?i)(~|\$home)[/\\]\.(ssh|aws|gnupg|netrc|npmrc|pypirc|docker|kube|azure|config[/\\]gcloud)\b|(?i)\bid_(rsa|ed25519|ecdsa)\b|(?i)\b(keychain|keyring|credential\s+manager|1password|op\s+read|bw\s+get|vault\s+(kv\s+)?read|aws\s+secretsmanager|gcloud\s+secrets)\b|(?i)\bprintenv\b|\bos\.environ\b|\bprocess\.env\b`,
			"$", "process.env", "os.environ", "getenv", "env[", ".env", "~", "$home", "id_", "keychain", "keyring", "credential", "1password", "op read", "bw get", "vault", "secretsmanager", "gcloud", "printenv")},
	{ID: "file-write", Title: "writes files outside the project",
		Why:   "Redirections, copies, moves, deletions and writes aimed at absolute paths, the home directory or system directories. Writing inside the working directory is what most skills are for, and is not on the label.",
		scope: inCode,
		pat: pat(`(?i)(>>?|\btee\s+(-a\s+)?|\b(cp|mv|install|ln|rsync)\s+(-\S+\s+)*\S+\s+|\b(rm|rmdir|mkdir|touch|chmod|chown)\s+(-\S+\s+)*)["']?(~|\$home\b|\$\{home\}|%userprofile%|%appdata%|\$env:(userprofile|appdata)|/(etc|usr|opt|var|tmp|bin|sbin|lib|library|applications|system|root|home|users|private)\b|[a-z]:\\)|\bopen\s*\(\s*(f?["'](/|~)|os\.path\.expanduser)[^)]*,\s*["'][wax]|\bwriteFile(Sync)?\s*\(\s*["'`+"`"+`](/|~)|\bos\.WriteFile\s*\(\s*"/|\bSet-Content\s+(-Path\s+)?["']?(c:\\|\$env:|~)|\bOut-File\s+(-FilePath\s+)?["']?(c:\\|\$env:|~)`,
			">", "tee", "cp", "mv", "install", "ln", "rsync", "rm", "mkdir", "touch", "chmod", "chown", "open", "writefile", "set-content", "out-file")},
	{ID: "package-install", Title: "installs packages",
		Why:   "npm, pnpm, yarn, bun, pip, pipx, uv, go, cargo, gem, brew, apt, dnf, yum, apk, choco, winget, scoop and composer installs, and running a package straight from a registry with npx, uvx or pipx run.",
		scope: anywhere,
		pat: pat(`(?i)\b(npm|pnpm|yarn|bun)\s+(i|install|add|ci)\b|\bnpx\s+(-y\s+|--yes\s+)?[@\w]|\b(pip3?|python3?\s+-m\s+pip)\s+install\b|\bpipx\s+(install|run)\b|\buv\s+(pip\s+install|add|tool\s+install|sync)\b|\buvx\s+\w|\bgo\s+(install|get)\s|\bcargo\s+(install|add)\b|\bgem\s+install\b|\bbrew\s+(install|tap)\b|\b(apt|apt-get|dnf|yum|zypper|apk)\s+(-\S+\s+)*(install|add)\b|\b(choco|winget|scoop)\s+install\b|\bcomposer\s+(require|install)\b|\bconda\s+install\b`,
			"npm", "pnpm", "yarn", "bun", "npx", "pip", "uv", "go ", "cargo", "gem", "brew", "apt", "dnf", "yum", "zypper", "apk", "choco", "winget", "scoop", "composer", "conda")},
	{ID: "external-include", Title: "depends on content that is not in the skill",
		Why:   "Instructions or code fetched when the skill runs: curl | sh, a script piped from the network, 'follow the instructions at https://...', a repository cloned and run, a container image, or a package run straight from a registry. The lockfile pins the pointer, not what it points at.",
		scope: anywhere,
		pat: pat(`(?i)\b(curl|wget)\b[^\n|]{0,300}\|\s*(sudo\s+)?\w*sh\b|(\bsource|\.|\b(ba|z)?sh)\s+<\(\s*(curl|wget)|\b(fetch|load|read|follow|download|get|import|apply)\b[^.\n]{0,40}\b(instructions?|rules|prompts?|guidelines|steps|skill|commands|config(uration)?)\b[^.\n]{0,40}\bfrom\s+<?https?://|\bgit\s+clone\b|\bdocker\s+run\b|\bnpx\s+(-y\s+|--yes\s+)?[@\w]|\buvx\s+\w|\bpipx\s+run\b|\b(iex|invoke-expression)\b`,
			"curl", "wget", "source", "<(", "http", "git", "docker", "npx", "uvx", "pipx", "iex", "invoke-expression")},
	{ID: "auto-trigger", Title: "comes into play without being asked",
		Why:   "Hooks in the front matter, which run on the agent's events, and a description that claims every conversation. Every skill the model may invoke is pulled in by its description; the label flags the ones that ask for everything.",
		skill: autoTriggerEvidence},
	{ID: "preapproved-tools", Title: "runs tools without asking",
		Why:   "allowed-tools in the front matter: tools the agent may use without a permission prompt while the skill is active.",
		skill: allowedToolsEvidence},
}

// Derive works out a skill's label.
func Derive(s *Skill) Label {
	var ev []Evidence
	urls := urlsIn(s)
	for i := range s.Files {
		f := &s.Files[i]
		for _, seg := range segments(f) {
			text := fold(seg.text)
			lower := lowerASCII(text)
			for _, c := range capabilities {
				if c.pat.re == nil || !(Rule{scope: c.scope}).applies(seg) {
					continue
				}
				// One piece of evidence per capability and segment is
				// plenty; the label is about whether, not how often.
				if loc := c.pat.find(text, lower); loc != nil {
					ev = append(ev, Evidence{Capability: c.ID, File: f.Path,
						Line: seg.line + strings.Count(text[:loc[0]], "\n"), Excerpt: excerpt(text, loc[0], loc[1])})
				}
			}
		}
	}
	for _, c := range capabilities {
		switch {
		case c.ID == "urls":
			// Already found; the label's hosts come from the same list.
			ev = append(ev, urlEvidence(urls)...)
		case c.skill != nil:
			ev = append(ev, c.skill(s)...)
		}
	}
	sort.SliceStable(ev, func(i, j int) bool {
		if ev[i].Capability != ev[j].Capability {
			return capIndex(ev[i].Capability) < capIndex(ev[j].Capability)
		}
		if ev[i].File != ev[j].File {
			return ev[i].File < ev[j].File
		}
		return ev[i].Line < ev[j].Line
	})
	l := Label{Capabilities: []string{}, Evidence: ev, Hosts: hosts(urls)}
	seen := map[string]bool{}
	for _, e := range ev {
		if !seen[e.Capability] {
			seen[e.Capability] = true
			l.Capabilities = append(l.Capabilities, e.Capability)
		}
	}
	sort.Slice(l.Capabilities, func(i, j int) bool { return capIndex(l.Capabilities[i]) < capIndex(l.Capabilities[j]) })
	return l
}

func capIndex(id string) int {
	for i, c := range capabilities {
		if c.ID == id {
			return i
		}
	}
	return len(capabilities)
}

// SortCapabilities puts capability IDs in label order.
func SortCapabilities(ids []string) {
	sort.SliceStable(ids, func(i, j int) bool { return capIndex(ids[i]) < capIndex(ids[j]) })
}

func shellEvidence(s *Skill) []Evidence {
	var out []Evidence
	for i := range s.Files {
		f := &s.Files[i]
		if lang := scriptLang(f.Path, f.text); shellLangs[lang] && !f.Binary {
			out = append(out, Evidence{Capability: "shell", File: f.Path, Excerpt: lang + " script"})
			continue
		}
		for _, seg := range segments(f) {
			switch {
			case seg.loadTime:
				out = append(out, Evidence{Capability: "shell", File: f.Path, Line: seg.line,
					Excerpt: "runs as the skill loads: " + excerpt(fold(seg.text), 0, min(len(seg.text), 60))})
			case seg.kind == segCode && shellLangs[seg.lang] && strings.TrimSpace(seg.text) != "":
				out = append(out, Evidence{Capability: "shell", File: f.Path, Line: seg.line,
					Excerpt: "```" + seg.lang + " block: " + excerpt(fold(seg.text), 0, min(len(seg.text), 60))})
			}
		}
	}
	if tools := s.frontString("allowed-tools"); shellTools.MatchString(tools) {
		out = append(out, Evidence{Capability: "shell", File: ManifestName, Excerpt: "allowed-tools: " + tools})
	}
	if s.Front["hooks"] != nil {
		out = append(out, Evidence{Capability: "shell", File: ManifestName, Excerpt: "hooks run commands"})
	}
	return out
}

var (
	shellTools       = regexp.MustCompile(`(?i)\b(bash|shell|powershell|terminal)\b`)
	networkToolNames = regexp.MustCompile(`(?i)\b(webfetch|websearch|fetch|browser)\b`)
)

func scriptEvidence(s *Skill) []Evidence {
	var out []Evidence
	for _, f := range s.Files {
		if f.Kind != KindFile {
			continue
		}
		if kind, ok := executableKind(f); ok {
			out = append(out, Evidence{Capability: "scripts", File: f.Path, Excerpt: kind})
			continue
		}
		if f.Binary || isMarkdown(f.Path) {
			continue
		}
		if lang := scriptLang(f.Path, f.text); lang != "" {
			out = append(out, Evidence{Capability: "scripts", File: f.Path, Excerpt: lang})
		}
	}
	return out
}

func networkTools(s *Skill) []Evidence {
	tools := s.frontString("allowed-tools")
	if networkToolNames.MatchString(tools) {
		return []Evidence{{Capability: "network", File: ManifestName, Excerpt: "allowed-tools: " + tools}}
	}
	return nil
}

func allowedToolsEvidence(s *Skill) []Evidence {
	if tools := strings.TrimSpace(s.frontString("allowed-tools")); tools != "" {
		return []Evidence{{Capability: "preapproved-tools", File: ManifestName, Excerpt: "allowed-tools: " + tools}}
	}
	return nil
}

func autoTriggerEvidence(s *Skill) []Evidence {
	var out []Evidence
	if s.Front["hooks"] != nil {
		out = append(out, Evidence{Capability: "auto-trigger", File: ManifestName, Excerpt: "hooks in the front matter"})
	}
	for _, f := range autoTrigger(s) {
		out = append(out, Evidence{Capability: "auto-trigger", File: ManifestName, Excerpt: f.Excerpt})
	}
	return out
}

// urlsIn finds every URL in a skill's text files, with where it is.
func urlsIn(s *Skill) []Evidence {
	var out []Evidence
	for _, f := range s.Files {
		if f.text == "" {
			continue
		}
		for _, m := range urlMatches(urlHost, f.text) {
			host := hostOf(f.text[m[2]:m[3]])
			if host == "" || placeholderHost(host) {
				continue
			}
			out = append(out, Evidence{Capability: "urls", File: f.Path, Line: lineOf(f.text, m[0]), Excerpt: host})
		}
	}
	return out
}

// urlEvidence keeps one piece of evidence per host.
func urlEvidence(urls []Evidence) []Evidence {
	var out []Evidence
	seen := map[string]bool{}
	for _, e := range urls {
		if !seen[e.Excerpt] {
			seen[e.Excerpt] = true
			out = append(out, e)
		}
	}
	return out
}

func hosts(urls []Evidence) []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range urls {
		if !seen[e.Excerpt] {
			seen[e.Excerpt] = true
			out = append(out, e.Excerpt)
		}
	}
	sort.Strings(out)
	return out
}

func hostOf(authority string) string {
	if at := strings.LastIndexByte(authority, '@'); at >= 0 {
		authority = authority[at+1:]
	}
	u, err := url.Parse("http://" + authority)
	if err != nil {
		return strings.ToLower(spellRunes(authority))
	}
	return strings.ToLower(spellRunes(strings.TrimRight(u.Hostname(), ".,;:")))
}

// placeholderHost is a host that is no destination at all: loopback, and
// the example domains reserved for documentation (RFC 2606).
func placeholderHost(host string) bool {
	return host == "localhost" || strings.HasPrefix(host, "127.") || host == "::1" || host == "0.0.0.0" ||
		strings.HasSuffix(host, ".localhost") || host == "example.com" || strings.HasSuffix(host, ".example.com") ||
		host == "example.org" || host == "example.net"
}
