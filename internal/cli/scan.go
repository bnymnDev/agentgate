package cli

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/bnymnDev/agentgate/internal/config"
	"github.com/bnymnDev/agentgate/internal/pinning"
	"github.com/bnymnDev/agentgate/internal/proxy"
)

func newScanCmd(g *globals) *cobra.Command {
	var (
		httpURL string
		headers []string
		envs    []string
		format  string
		failOn  string
		badge   bool
		colour  string
	)
	cmd := &cobra.Command{
		Use:   "scan [-- command [args...]]",
		Short: "Scan an MCP server's tools, prompts and resources for signs of poisoning",
		Long: `Start an MCP server, read everything it offers the model — tools,
prompts, resources, resource templates and its instructions — and scan it for
the marks of a poisoned definition: text hidden in invisible Unicode,
instructions addressed to the model, pointers at credentials and agent
configuration, and one server's tool talking about another's.

	agentgate scan -- npx -y @modelcontextprotocol/server-filesystem /tmp
	agentgate scan --http https://mcp.example.com/mcp --header "Authorization: Bearer $TOKEN"
	agentgate scan                      # every upstream in the config

No proxy runs and nothing is pinned: this only reads. It exits 1 when it
finds something, so it works as a gate in CI and before you install a
server. --format sarif writes SARIF 2.1.0 for GitHub code scanning, markdown
a report for a pull request, and --badge a shields.io badge for a server's
README.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			useColour, err := colourFlag(colour)
			if err != nil {
				return err
			}
			switch format {
			case "text", "json", "sarif", "markdown":
			default:
				return fmt.Errorf("--format: want text, json, sarif or markdown, got %q", format)
			}
			switch failOn {
			case "finding", "none":
			default:
				return fmt.Errorf("--fail-on: want finding or none, got %q", failOn)
			}

			var cfg *config.Config
			if len(args) > 0 || httpURL != "" {
				cfg, err = adHocConfig(args, httpURL, headers, envs)
			} else {
				cfg, err = g.load()
			}
			if err != nil {
				return err
			}
			// Nothing the user pinned or accepted is touched, or consulted: a
			// scan reports what is there.
			dir, err := os.MkdirTemp("", "agentgate-scan-*")
			if err != nil {
				return err
			}
			defer func() { _ = os.RemoveAll(dir) }()
			cfg.Pinning.Mode, cfg.Pinning.Scan, cfg.Pinning.Lockfile = "warn", "warn", filepath.Join(dir, "scan.lock")
			if err := cfg.Pinning.Normalize(cfg.Path); err != nil {
				return err
			}

			p, err := proxy.New(proxy.Options{Config: cfg, Logger: g.quietLogger(), DownstreamTransport: "scan", Pinning: proxy.PinningInspect})
			if err != nil {
				return err
			}
			if err := p.Connect(cmd.Context()); err != nil {
				return err
			}
			report := buildScanReport(p.Upstreams(), p.ToolReports(), cfg.Path)
			_ = p.Close()

			out := cmd.OutOrStdout()
			switch format {
			case "json":
				err = writeJSON(out, report)
			case "sarif":
				err = writeJSON(out, report.sarif())
			case "markdown":
				_, err = io.WriteString(out, report.markdown())
			default:
				report.text(&lineWriter{out: out, colour: useColour})
			}
			if err != nil {
				return err
			}
			if badge {
				fmt.Fprintln(out, report.badge())
			}
			if report.Findings > 0 && failOn == "finding" {
				return errExitDenied
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&httpURL, "http", "", "scan the Streamable HTTP server at this URL")
	cmd.Flags().StringArrayVar(&headers, "header", nil, `a header for --http, as "Name: value" (repeatable)`)
	cmd.Flags().StringArrayVar(&envs, "env", nil, "an environment variable for the server, as NAME=value (repeatable)")
	cmd.Flags().StringVar(&format, "format", "text", "text, json, sarif or markdown")
	cmd.Flags().StringVar(&failOn, "fail-on", "finding", "finding (exit 1 when something is found) or none")
	cmd.Flags().BoolVar(&badge, "badge", false, "also print a shields.io badge with the verdict, for a README")
	cmd.Flags().StringVar(&colour, "color", "auto", "colour the output: auto, always or never")
	return cmd
}

// adHocConfig is a config with one upstream: the server named on the command
// line.
func adHocConfig(args []string, httpURL string, headers, envs []string) (*config.Config, error) {
	if len(args) > 0 && httpURL != "" {
		return nil, errors.New("scan either a command or --http, not both")
	}
	up := map[string]any{"name": serverName(args, httpURL)}
	if httpURL != "" {
		up["http"] = httpURL
		h := map[string]string{}
		for _, kv := range headers {
			k, v, ok := strings.Cut(kv, ":")
			if !ok {
				return nil, fmt.Errorf("--header %q: want \"Name: value\"", kv)
			}
			h[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
		if len(h) > 0 {
			up["headers"] = h
		}
	} else {
		up["stdio"] = args
	}
	if len(envs) > 0 {
		e := map[string]string{}
		for _, kv := range envs {
			k, v, ok := strings.Cut(kv, "=")
			if !ok {
				return nil, fmt.Errorf("--env %q: want NAME=value", kv)
			}
			e[k] = v
		}
		up["env"] = e
	}
	raw, err := yaml.Marshal(map[string]any{
		"version":   1,
		"upstreams": []any{up},
		"audit":     map[string]any{"enabled": false},
		"policy":    map[string]any{"default": "allow"},
	})
	if err != nil {
		return nil, err
	}
	return config.Parse(raw)
}

var nonName = regexp.MustCompile(`[^a-z0-9-]+`)

// serverName is a readable upstream name for a command or a URL: the package
// or the binary, or the host.
func serverName(args []string, httpURL string) string {
	base := "server"
	if httpURL != "" {
		if u, err := url.Parse(httpURL); err == nil && u.Hostname() != "" {
			base = u.Hostname()
		}
	} else {
		for _, a := range args {
			if strings.HasPrefix(a, "-") || a == "npx" || a == "uvx" || a == "docker" || a == "run" || a == "node" || a == "python" || a == "python3" {
				continue
			}
			base = filepath.Base(a)
			if i := strings.LastIndex(base, "/"); i >= 0 {
				base = base[i+1:]
			}
			break
		}
	}
	name := strings.Trim(nonName.ReplaceAllString(strings.ToLower(base), "-"), "-")
	if name == "" {
		name = "server"
	}
	return name
}

// scanReport is what a scan found.
type scanReport struct {
	Servers     []proxy.UpstreamInfo `json:"servers"`
	Definitions []scannedDefinition  `json:"definitions"`
	// Counts are the definitions by kind.
	Counts   map[string]int `json:"counts"`
	Findings int            `json:"findings"`
	// Config is the config the servers came from, if any, for SARIF.
	Config string `json:"-"`
}

type scannedDefinition struct {
	Upstream string            `json:"upstream"`
	Kind     string            `json:"kind"`
	Ref      string            `json:"ref"`
	Findings []pinning.Finding `json:"findings,omitempty"`
}

func buildScanReport(servers []proxy.UpstreamInfo, reports []proxy.ToolReport, configPath string) *scanReport {
	r := &scanReport{Servers: servers, Counts: map[string]int{}, Config: configPath}
	for _, tr := range reports {
		if tr.Status == pinning.StatusRemoved {
			continue
		}
		kind := tr.Current.What()
		r.Counts[kind]++
		findings := append(append([]pinning.Finding(nil), tr.Findings...), tr.Accepted...)
		r.Findings += len(findings)
		r.Definitions = append(r.Definitions, scannedDefinition{Upstream: tr.Upstream, Kind: kind, Ref: tr.Tool, Findings: findings})
	}
	sort.SliceStable(r.Definitions, func(i, j int) bool {
		a, b := r.Definitions[i], r.Definitions[j]
		if (len(a.Findings) > 0) != (len(b.Findings) > 0) {
			return len(a.Findings) > 0
		}
		if a.Upstream != b.Upstream {
			return a.Upstream < b.Upstream
		}
		return a.Ref < b.Ref
	})
	return r
}

func (r *scanReport) flagged() int {
	n := 0
	for _, d := range r.Definitions {
		if len(d.Findings) > 0 {
			n++
		}
	}
	return n
}

func (r *scanReport) summary() string {
	var parts []string
	for _, k := range []string{"tool", "prompt", "resource", "resource template", "instructions"} {
		n := r.Counts[k]
		switch {
		case n == 0:
		case k == "instructions":
			parts = append(parts, "instructions")
		case n == 1:
			parts = append(parts, fmt.Sprintf("1 %s", k))
		default:
			parts = append(parts, fmt.Sprintf("%d %ss", n, k))
		}
	}
	if len(parts) == 0 {
		return "nothing offered"
	}
	return strings.Join(parts, ", ")
}

func (r *scanReport) verdict() string {
	if r.Findings == 0 {
		return "clean"
	}
	return fmt.Sprintf("%d finding(s) in %d definition(s)", r.Findings, r.flagged())
}

func (r *scanReport) text(w *lineWriter) {
	out := w.out
	for _, s := range r.Servers {
		what := s.Transport
		if s.Server != "" {
			what = strings.TrimSpace(s.Server+" "+s.Version) + ", " + s.Transport
		}
		if !s.Connected {
			what += ", not reachable"
		}
		fmt.Fprintf(out, "%s  (%s)\n", s.Name, what)
	}
	fmt.Fprintf(out, "\n%s\n", r.summary())
	for _, d := range r.Definitions {
		if len(d.Findings) == 0 {
			continue
		}
		fmt.Fprintf(out, "\n%s.%s  %s\n", d.Upstream, d.Ref, w.paint(colourYellow, d.Kind))
		for _, f := range d.Findings {
			fmt.Fprintf(out, "  %s  %s: %s\n", w.paint(colourRed, f.Kind), f.Where, f.Detail)
			if f.Excerpt != "" {
				fmt.Fprintf(out, "           %s\n", w.revealed(fmt.Sprintf("%q", pinning.Reveal(f.Excerpt))))
			}
		}
	}
	v := r.verdict()
	if r.Findings == 0 {
		v = w.paint(colourGreen, v)
	} else {
		v = w.paint(colourRed, v)
	}
	fmt.Fprintf(out, "\n%s\n", v)
}

func (r *scanReport) badge() string {
	msg, colourName := "clean", "brightgreen"
	if r.Findings > 0 {
		msg, colourName = fmt.Sprintf("%d findings", r.Findings), "red"
	}
	return fmt.Sprintf("[![agentgate scan: %s](https://img.shields.io/badge/agentgate_scan-%s-%s)](https://github.com/bnymnDev/agentgate#scan-a-server)",
		msg, strings.ReplaceAll(url.PathEscape(msg), "%20", "_"), colourName)
}

func (r *scanReport) markdown() string {
	var b strings.Builder
	b.WriteString("### agentgate scan\n\n")
	for _, s := range r.Servers {
		fmt.Fprintf(&b, "- **%s** %s %s (%s)\n", mdEscape(s.Name), mdEscape(s.Server), mdEscape(s.Version), s.Transport)
	}
	fmt.Fprintf(&b, "\n%s — **%s**\n\n%s\n", r.summary(), r.verdict(), r.badge())
	if r.Findings == 0 {
		return b.String()
	}
	b.WriteString("\n| Definition | Kind | Finding | Where | Text |\n|---|---|---|---|---|\n")
	for _, d := range r.Definitions {
		for _, f := range d.Findings {
			fmt.Fprintf(&b, "| `%s.%s` | %s | %s | %s | %s |\n", d.Upstream, mdEscape(d.Ref), d.Kind, f.Kind, mdEscape(f.Where),
				mdEscape(truncate(pinning.Reveal(f.Detail+": "+f.Excerpt), 200)))
		}
	}
	return b.String()
}

func mdEscape(s string) string {
	return strings.NewReplacer("|", `\|`, "\n", " ", "`", "'", "<", "&lt;", ">", "&gt;").Replace(s)
}

// SARIF 2.1.0, as much of it as code scanning reads.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string       `json:"id"`
	ShortDescription sarifMessage `json:"shortDescription"`
	HelpURI          string       `json:"helpUri"`
	Properties       struct {
		Tags             []string `json:"tags"`
		SecuritySeverity string   `json:"security-severity"`
	} `json:"properties"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifMessage      `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
}

type sarifLocation struct {
	PhysicalLocation struct {
		ArtifactLocation struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
		Region struct {
			StartLine int `json:"startLine"`
		} `json:"region"`
	} `json:"physicalLocation"`
	LogicalLocations []struct {
		Name               string `json:"name"`
		FullyQualifiedName string `json:"fullyQualifiedName"`
		Kind               string `json:"kind"`
	} `json:"logicalLocations"`
}

var sarifRules = []struct{ id, text, severity string }{
	{pinning.KindInvisible, "Text hidden from people in invisible or reordering characters", "8.5"},
	{pinning.KindInstruction, "Text addressed to the model instead of describing the definition", "7.5"},
	{pinning.KindCredentials, "Points the model at credentials or agent configuration", "7.0"},
	{pinning.KindShadowing, "Talks about another server's tools", "6.0"},
}

func (r *scanReport) sarif() sarifLog {
	driver := sarifDriver{Name: "agentgate", Version: version(), InformationURI: "https://github.com/bnymnDev/agentgate"}
	for _, rule := range sarifRules {
		sr := sarifRule{ID: "mcp-" + rule.id, ShortDescription: sarifMessage{Text: rule.text},
			HelpURI: "https://github.com/bnymnDev/agentgate/blob/main/docs/guardrails.md#tool-poisoning"}
		sr.Properties.Tags = []string{"security", "mcp"}
		sr.Properties.SecuritySeverity = rule.severity
		driver.Rules = append(driver.Rules, sr)
	}
	// Code scanning wants a file; the config the servers came from is the
	// one there is, or else a stand-in.
	uri := "agentgate-scan"
	if r.Config != "" {
		uri = filepath.ToSlash(r.Config)
		if wd, err := os.Getwd(); err == nil {
			if rel, err := filepath.Rel(wd, r.Config); err == nil && !strings.HasPrefix(rel, "..") {
				uri = filepath.ToSlash(rel)
			}
		}
	}
	results := []sarifResult{}
	for _, d := range r.Definitions {
		for _, f := range d.Findings {
			res := sarifResult{RuleID: "mcp-" + f.Kind, Level: "error",
				Message:             sarifMessage{Text: fmt.Sprintf("%s %s.%s, %s: %s", d.Kind, d.Upstream, d.Ref, f.Where, f.Detail)},
				PartialFingerprints: map[string]string{"agentgate/v1": d.Upstream + "/" + d.Ref + "/" + f.Key()}}
			if f.Excerpt != "" {
				res.Message.Text += fmt.Sprintf(" — %q", truncate(pinning.Reveal(f.Excerpt), 300))
			}
			var loc sarifLocation
			loc.PhysicalLocation.ArtifactLocation.URI = uri
			loc.PhysicalLocation.Region.StartLine = 1
			loc.LogicalLocations = append(loc.LogicalLocations, struct {
				Name               string `json:"name"`
				FullyQualifiedName string `json:"fullyQualifiedName"`
				Kind               string `json:"kind"`
			}{Name: d.Ref, FullyQualifiedName: d.Upstream + "." + d.Ref, Kind: "member"})
			res.Locations = []sarifLocation{loc}
			results = append(results, res)
		}
	}
	return sarifLog{Schema: "https://json.schemastore.org/sarif-2.1.0.json", Version: "2.1.0",
		Runs: []sarifRun{{Tool: sarifTool{Driver: driver}, Results: results}}}
}
