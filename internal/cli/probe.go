package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"

	"github.com/bnymnDev/agentgate/internal/config"
	"github.com/bnymnDev/agentgate/internal/pinning"
	"github.com/bnymnDev/agentgate/internal/policy"
	"github.com/bnymnDev/agentgate/internal/proxy"
)

// probeResult is one tool, probed or not.
type probeResult struct {
	Upstream string            `json:"upstream"`
	Tool     string            `json:"tool"`
	Probed   bool              `json:"probed"`
	Skipped  string            `json:"skipped,omitempty"`
	Args     map[string]any    `json:"args,omitempty"`
	Error    string            `json:"error,omitempty"`
	Bytes    int               `json:"bytes,omitempty"`
	Findings []pinning.Finding `json:"findings,omitempty"`
}

func newProbeCmd(g *globals) *cobra.Command {
	var (
		httpURL  string
		headers  []string
		envs     []string
		tools    []string
		argSpecs []string
		asJSON   bool
		webhook  string
		timeout  time.Duration
	)
	cmd := &cobra.Command{
		Use:   "probe [-- command [args...]]",
		Short: "Call a server's read-only tools and scan what comes back for injection",
		Long: `A smoke detector for prompt injection. Where scan reads what a server says
about its tools, probe calls them — the read-only ones only — with arguments
made up from their schemas, the way an agent would, and scans every answer
for what an injection looks like: text hidden in invisible characters,
instructions addressed to the model, chat-template tokens, image URLs that
leak what fills them.

	agentgate probe -- npx -y @acme/news-mcp
	agentgate probe --tool 'search_*' --arg 'search_issues={"query":"bug"}'

A tool is called only if the server marks it read-only (readOnlyHint), or
you name it with --tool. Run it from cron against the servers whose content
you do not control — a web search, an issue tracker, a mailbox — and
--webhook posts the report when something is found. Exits 1 then too.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			var cfg *config.Config
			var err error
			if len(args) > 0 || httpURL != "" {
				cfg, err = adHocConfig(args, httpURL, headers, envs)
			} else {
				cfg, err = g.load()
			}
			if err != nil {
				return err
			}
			named, err := globList(tools)
			if err != nil {
				return err
			}
			fixed := map[string]map[string]any{}
			for _, spec := range argSpecs {
				name, raw, ok := strings.Cut(spec, "=")
				var a map[string]any
				if !ok || json.Unmarshal([]byte(raw), &a) != nil {
					return fmt.Errorf("--arg %q: want tool={json object}", spec)
				}
				fixed[name] = a
			}
			dir, err := os.MkdirTemp("", "agentgate-probe-*")
			if err != nil {
				return err
			}
			defer func() { _ = os.RemoveAll(dir) }()
			cfg.Pinning.Mode, cfg.Pinning.Scan, cfg.Pinning.Lockfile = "warn", "warn", filepath.Join(dir, "probe.lock")
			if err := cfg.Pinning.Normalize(cfg.Path); err != nil {
				return err
			}
			p, err := proxy.New(proxy.Options{Config: cfg, Logger: g.quietLogger(), DownstreamTransport: "probe", Pinning: proxy.PinningInspect})
			if err != nil {
				return err
			}
			if err := p.Connect(cmd.Context()); err != nil {
				return err
			}
			defer func() { _ = p.Close() }()

			var results []probeResult
			found := 0
			for _, r := range p.ToolReports() {
				d := r.Current
				if d.Kind != "" || r.Status == pinning.StatusRemoved {
					continue
				}
				pr := probeResult{Upstream: r.Upstream, Tool: d.Name}
				readOnly := annotationReadOnly(d.Annotations)
				chosen := matchesAny(named, d.Name) || matchesAny(named, r.Upstream+"."+d.Name)
				switch {
				case len(named) > 0 && !chosen:
					pr.Skipped = "not named with --tool"
				case len(named) == 0 && !readOnly:
					pr.Skipped = "not marked read-only; name it with --tool to call it anyway"
				}
				if pr.Skipped == "" {
					pr.Args = fixed[d.Name]
					if pr.Args == nil {
						pr.Args = argsFromSchema(d.InputSchema)
					}
					ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
					res, err := p.CallUpstream(ctx, r.Upstream, d.Name, pr.Args)
					cancel()
					pr.Probed = true
					switch {
					case err != nil:
						pr.Error = oneLine(err)
					default:
						text := resultText(res)
						pr.Bytes = len(text)
						if res.IsError {
							pr.Error = "the tool returned an error: " + truncate(oneLine(fmt.Errorf("%s", text)), 120)
						}
						pr.Findings = pinning.ScanResult(text)
						found += len(pr.Findings)
					}
				}
				results = append(results, pr)
			}
			sort.Slice(results, func(i, j int) bool {
				if results[i].Upstream != results[j].Upstream {
					return results[i].Upstream < results[j].Upstream
				}
				return results[i].Tool < results[j].Tool
			})

			out := cmd.OutOrStdout()
			report := map[string]any{"at": time.Now().UTC(), "findings": found, "tools": results}
			if asJSON {
				if err := writeJSON(out, report); err != nil {
					return err
				}
			} else {
				probed := 0
				for _, r := range results {
					name := r.Upstream + "." + r.Tool
					switch {
					case !r.Probed:
						fmt.Fprintf(out, "%-8s %s: %s\n", "skipped", name, r.Skipped)
						continue
					case r.Error != "" && len(r.Findings) == 0:
						fmt.Fprintf(out, "%-8s %s: %s\n", "error", name, r.Error)
					case len(r.Findings) == 0:
						fmt.Fprintf(out, "%-8s %s (%d bytes)\n", "clean", name, r.Bytes)
					default:
						fmt.Fprintf(out, "%-8s %s\n", "FOUND", name)
						for _, f := range r.Findings {
							fmt.Fprintf(out, "         %s", f.Detail)
							if f.Excerpt != "" {
								fmt.Fprintf(out, ": %q", truncate(pinning.Reveal(f.Excerpt), 100))
							}
							fmt.Fprintln(out)
						}
					}
					probed++
				}
				fmt.Fprintf(out, "\n%d tools probed, %d findings\n", probed, found)
			}
			if found > 0 && webhook != "" {
				body, _ := json.Marshal(report)
				req, err := http.NewRequestWithContext(cmd.Context(), http.MethodPost, webhook, bytes.NewReader(body))
				if err == nil {
					req.Header.Set("Content-Type", "application/json")
					req.Header.Set("Title", fmt.Sprintf("agentgate probe: %d findings", found))
					if resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req); err != nil {
						fmt.Fprintf(cmd.ErrOrStderr(), "webhook: %s\n", oneLine(err))
					} else {
						_ = resp.Body.Close()
					}
				}
			}
			if found > 0 {
				return errExitDenied
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&httpURL, "http", "", "probe the Streamable HTTP server at this URL")
	cmd.Flags().StringArrayVar(&headers, "header", nil, `a header for --http, as "Name: value" (repeatable)`)
	cmd.Flags().StringArrayVar(&envs, "env", nil, "an environment variable for the server, as NAME=value (repeatable)")
	cmd.Flags().StringArrayVar(&tools, "tool", nil, "call only these tools, read-only or not: globs over tool or upstream.tool (repeatable)")
	cmd.Flags().StringArrayVar(&argSpecs, "arg", nil, `arguments for a tool, as tool={"json":"object"}, instead of made-up ones (repeatable)`)
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the report as JSON")
	cmd.Flags().StringVar(&webhook, "webhook", "", "POST the report as JSON here when something is found (an ntfy topic URL works)")
	cmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "how long one call may take")
	return cmd
}

func globList(globs []string) ([]*regexp.Regexp, error) {
	var out []*regexp.Regexp
	for _, g := range globs {
		re, err := policy.CompileGlob(g)
		if err != nil {
			return nil, fmt.Errorf("--tool %q: %w", g, err)
		}
		out = append(out, re)
	}
	return out, nil
}

func matchesAny(res []*regexp.Regexp, s string) bool {
	for _, re := range res {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

func annotationReadOnly(raw json.RawMessage) bool {
	var a struct {
		ReadOnly bool `json:"readOnlyHint"`
	}
	return json.Unmarshal(raw, &a) == nil && a.ReadOnly
}

func resultText(res *mcp.CallToolResult) string {
	var parts []string
	for _, c := range res.Content {
		switch c := c.(type) {
		case *mcp.TextContent:
			parts = append(parts, c.Text)
		case *mcp.EmbeddedResource:
			if c.Resource != nil {
				parts = append(parts, c.Resource.Text)
			}
		}
	}
	if len(parts) == 0 && res.StructuredContent != nil {
		raw, _ := json.Marshal(res.StructuredContent)
		parts = append(parts, string(raw))
	}
	return strings.Join(parts, "\n")
}

// argsFromSchema makes up arguments a schema accepts: its defaults and
// examples where it has them, the first of an enum, and plain values that
// suit the name otherwise. Only required properties are filled.
func argsFromSchema(raw json.RawMessage) map[string]any {
	var s schemaNode
	_ = json.Unmarshal(raw, &s)
	out := map[string]any{}
	for _, name := range s.Required {
		if prop, ok := s.Properties[name]; ok {
			out[name] = valueFor(name, prop, 0)
		}
	}
	return out
}

type schemaNode struct {
	Type       any                   `json:"type"`
	Format     string                `json:"format"`
	Enum       []any                 `json:"enum"`
	Default    any                   `json:"default"`
	Examples   []any                 `json:"examples"`
	Minimum    *float64              `json:"minimum"`
	MinItems   int                   `json:"minItems"`
	Items      *schemaNode           `json:"items"`
	Properties map[string]schemaNode `json:"properties"`
	Required   []string              `json:"required"`
}

func (s schemaNode) typeName() string {
	switch t := s.Type.(type) {
	case string:
		return t
	case []any:
		for _, x := range t {
			if str, ok := x.(string); ok && str != "null" {
				return str
			}
		}
	}
	return "string"
}

func valueFor(name string, s schemaNode, depth int) any {
	switch {
	case s.Default != nil:
		return s.Default
	case len(s.Examples) > 0:
		return s.Examples[0]
	case len(s.Enum) > 0:
		return s.Enum[0]
	}
	n := strings.ToLower(name)
	switch s.typeName() {
	case "integer", "number":
		if s.Minimum != nil {
			return *s.Minimum
		}
		return 1
	case "boolean":
		return false
	case "array":
		items := []any{}
		if s.Items != nil && s.MinItems > 0 && depth < 3 {
			for range s.MinItems {
				items = append(items, valueFor(name, *s.Items, depth+1))
			}
		}
		return items
	case "object":
		obj := map[string]any{}
		if depth < 3 {
			for _, r := range s.Required {
				obj[r] = valueFor(r, s.Properties[r], depth+1)
			}
		}
		return obj
	}
	switch {
	case s.Format == "uri" || s.Format == "url" || strings.Contains(n, "url") || strings.Contains(n, "uri"):
		return "https://example.com/"
	case s.Format == "email" || strings.Contains(n, "email"):
		return "probe@example.com"
	case s.Format == "date-time":
		return time.Now().UTC().Format(time.RFC3339)
	case s.Format == "date":
		return time.Now().UTC().Format(time.DateOnly)
	case strings.Contains(n, "path") || strings.Contains(n, "file") || strings.Contains(n, "dir"):
		return "."
	case strings.Contains(n, "id"):
		return "1"
	}
	return "agentgate"
}
