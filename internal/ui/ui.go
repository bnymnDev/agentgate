// Package ui serves the agentgate web interface: a read-only view of the audit
// database, the loaded policy, and the approvals inbox.
//
// It is plain server-rendered HTML with htmx for the few interactive bits. The
// templates and both vendored assets are embedded, so the binary serves the
// whole UI with no network access and no build step.
package ui

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/bnymnDev/agentgate/internal/audit"
	"github.com/bnymnDev/agentgate/internal/config"
	"github.com/bnymnDev/agentgate/internal/killswitch"
	"github.com/bnymnDev/agentgate/internal/policy"
	"github.com/bnymnDev/agentgate/internal/proxy"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

// Approvals is the part of the proxy's inbox the UI needs. It is an interface
// so that "agentgate ui" can serve the audit database on its own, with no proxy
// running behind it.
type Approvals interface {
	Pending() []proxy.PendingApproval
	Resolve(id string, choice proxy.Choice, who string) bool
}

// Options configure the UI server.
type Options struct {
	Store *audit.Store
	// Config returns the configuration currently in force. Required.
	Config func() *config.Config
	// Approvals is the pending "ask" queue, or nil when nothing can be approved.
	Approvals Approvals
	// Reload re-reads the config file and swaps the policy into the running
	// proxy. Nil disables the reload button.
	Reload func() (*config.Config, error)
	// Freeze and Unfreeze throw and lift the kill switch. Nil hides the
	// buttons.
	Freeze   func(reason, by string) error
	Unfreeze func() error
	Logger   *slog.Logger
	Version  string
}

// Server renders the UI.
type Server struct {
	opts Options
	log  *slog.Logger
	tmpl map[string]*template.Template
}

// New builds the UI server and parses the templates.
func New(opts Options) (*Server, error) {
	if opts.Config == nil {
		return nil, fmt.Errorf("ui: no config accessor")
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	s := &Server{opts: opts, log: opts.Logger, tmpl: map[string]*template.Template{}}
	// Every page is parsed together with the layout, which is how html/template
	// wants overriding blocks to be set up.
	for _, page := range []string{"sessions", "session", "call", "policy", "approvals"} {
		t, err := template.New("layout.html").Funcs(funcs()).
			ParseFS(templateFS, "templates/layout.html", "templates/"+page+".html")
		if err != nil {
			return nil, fmt.Errorf("ui: parsing %s: %w", page, err)
		}
		s.tmpl[page] = t
	}
	// The partial-only templates reuse the definitions of their page.
	return s, nil
}

// Handler returns the router.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.FileServerFS(staticFS))
	mux.HandleFunc("GET /{$}", s.handleSessions)
	mux.HandleFunc("GET /partials/sessions", s.handleSessionsPartial)
	mux.HandleFunc("GET /sessions/{id}", s.handleSession)
	mux.HandleFunc("GET /partials/calls", s.handleCallsPartial)
	mux.HandleFunc("GET /calls/{id}", s.handleCall)
	mux.HandleFunc("GET /policy", s.handlePolicy)
	mux.HandleFunc("POST /policy/validate", s.handlePolicyValidate)
	mux.HandleFunc("POST /policy/reload", s.handlePolicyReload)
	mux.HandleFunc("GET /approvals", s.handleApprovals)
	mux.HandleFunc("GET /partials/approvals", s.handleApprovalsPartial)
	mux.HandleFunc("POST /approvals/{id}/{verb}", s.handleApprovalDecide)
	mux.HandleFunc("POST /freeze", s.handleFreeze)
	mux.HandleFunc("POST /unfreeze", s.handleUnfreeze)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"ok"}`)
	})
	return mux
}

// page is the data every template gets, on top of its own fields.
type page struct {
	Title        string
	Nav          string
	Version      string
	AuditPath    string
	PendingCount int
	// Frozen and FreezeReason describe the kill switch; CanFreeze says whether
	// this instance can toggle it.
	Frozen       bool
	FreezeReason string
	FrozenBy     string
	FrozenAt     time.Time
	CanFreeze    bool
	Shadow       bool
}

func (s *Server) page(title, nav string) page {
	cfg := s.opts.Config()
	p := page{Title: title, Nav: nav, Version: s.opts.Version, CanFreeze: s.opts.Freeze != nil && s.opts.Unfreeze != nil}
	if cfg != nil {
		p.AuditPath = cfg.Audit.Path
		p.Shadow = cfg.Policy.IsShadow()
		if st, frozen := killswitch.Status(cfg.FreezeFile()); frozen {
			p.Frozen, p.FreezeReason, p.FrozenBy, p.FrozenAt = true, st.Reason, st.By, st.At
		}
	}
	if s.opts.Approvals != nil {
		p.PendingCount = len(s.opts.Approvals.Pending())
	}
	return p
}

func (s *Server) render(w http.ResponseWriter, name string, data any) {
	t, ok := s.tmpl[name]
	if !ok {
		s.fail(w, fmt.Errorf("unknown page %q", name))
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, "layout", data); err != nil {
		s.log.Error("rendering page", "page", name, "error", err)
	}
}

func (s *Server) renderPartial(w http.ResponseWriter, page, name string, data any) {
	t, ok := s.tmpl[page]
	if !ok {
		s.fail(w, fmt.Errorf("unknown page %q", page))
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, name, data); err != nil {
		s.log.Error("rendering partial", "partial", name, "error", err)
	}
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	s.log.Error("ui request failed", "error", err)
	http.Error(w, err.Error(), http.StatusInternalServerError)
}

// funcs are the template helpers. They are deliberately few: formatting belongs
// in the templates, logic belongs in Go.
func funcs() template.FuncMap {
	return template.FuncMap{
		"ts": func(t time.Time) string { return t.Local().Format("2006-01-02 15:04:05") },
		"dur": func(d time.Duration) string {
			switch {
			case d < time.Second:
				return d.Round(time.Millisecond).String()
			case d < time.Minute:
				return d.Round(100 * time.Millisecond).String()
			default:
				return d.Round(time.Second).String()
			}
		},
		"short": func(s string) string {
			if len(s) <= 10 {
				return s
			}
			return s[:10]
		},
		"tokens": func(n int) string {
			switch {
			case n >= 1_000_000:
				return fmt.Sprintf("%.1fM", float64(n)/1e6)
			case n >= 1000:
				return fmt.Sprintf("%.1fk", float64(n)/1e3)
			default:
				return fmt.Sprint(n)
			}
		},
		"pretty":     pretty,
		"isHoneypot": func(ruleID string) bool { return ruleID == policy.RuleHoneypot },
	}
}

// pretty formats stored JSON for display, falling back to the raw text for
// anything that is not JSON.
func pretty(raw json.RawMessage) string {
	if len(raw) == 0 {
		return "—"
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return string(raw)
	}
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return string(raw)
	}
	return string(out)
}

// parseSince turns the UI's time-range picker into a cutoff.
func parseSince(v string) time.Time {
	if v == "" {
		return time.Time{}
	}
	d, err := config.ParseDuration(v)
	if err != nil || d <= 0 {
		return time.Time{}
	}
	return time.Now().Add(-d)
}

func decisionParam(v string) policy.Action {
	a := policy.Action(strings.TrimSpace(v))
	if a.Valid() {
		return a
	}
	return ""
}
