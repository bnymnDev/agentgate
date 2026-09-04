package ui

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/bnymnDev/agentgate/internal/audit"
	"github.com/bnymnDev/agentgate/internal/config"
	"github.com/bnymnDev/agentgate/internal/policy"
	"github.com/bnymnDev/agentgate/internal/proxy"
)

type sessionsData struct {
	page
	Stats    *audit.Stats
	Sessions []*audit.Session
	Since    string
}

func (s *Server) sessionsData(r *http.Request) (*sessionsData, error) {
	since := r.URL.Query().Get("since")
	if since == "" && !r.URL.Query().Has("since") {
		since = "24h"
	}
	stats, err := s.opts.Store.Stats(r.Context(), parseSince(since))
	if err != nil {
		return nil, err
	}
	sessions, err := s.opts.Store.ListSessions(r.Context(), audit.SessionFilter{Since: parseSince(since)})
	if err != nil {
		return nil, err
	}
	return &sessionsData{
		page:     s.page("Sessions", "sessions"),
		Stats:    stats,
		Sessions: sessions,
		Since:    since,
	}, nil
}

func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	data, err := s.sessionsData(r)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, "sessions", data)
}

func (s *Server) handleSessionsPartial(w http.ResponseWriter, r *http.Request) {
	data, err := s.sessionsData(r)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.renderPartial(w, "sessions", "session-rows", data)
}

type sessionData struct {
	page
	Session  *audit.Session
	Calls    []*audit.Call
	Tool     string
	Decision string
}

func (s *Server) sessionData(r *http.Request, id string) (*sessionData, error) {
	sess, err := s.opts.Store.GetSession(r.Context(), id)
	if err != nil {
		return nil, err
	}
	q := r.URL.Query()
	calls, err := s.opts.Store.ListCalls(r.Context(), audit.CallFilter{
		SessionID: sess.ID,
		Tool:      q.Get("tool"),
		Decision:  decisionParam(q.Get("decision")),
	})
	if err != nil {
		return nil, err
	}
	return &sessionData{
		page:     s.page("Session "+sess.ID, "sessions"),
		Session:  sess,
		Calls:    calls,
		Tool:     q.Get("tool"),
		Decision: q.Get("decision"),
	}, nil
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	data, err := s.sessionData(r, r.PathValue("id"))
	if errors.Is(err, audit.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, "session", data)
}

func (s *Server) handleCallsPartial(w http.ResponseWriter, r *http.Request) {
	data, err := s.sessionData(r, r.URL.Query().Get("session"))
	if err != nil {
		s.fail(w, err)
		return
	}
	s.renderPartial(w, "session", "call-rows", data)
}

type callData struct {
	page
	Call *audit.Call
}

func (s *Server) handleCall(w http.ResponseWriter, r *http.Request) {
	call, err := s.opts.Store.GetCall(r.Context(), r.PathValue("id"))
	if errors.Is(err, audit.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, "call", &callData{page: s.page(call.Tool, "sessions"), Call: call})
}

type upstreamView struct {
	Name      string
	Transport string
	Target    string
	Prefix    string
	Timeout   string
}

type conditionView struct {
	Path    string
	Summary string
}

type ruleView struct {
	ID     string
	Tool   string
	Action policy.Action
	Reason string
	When   []conditionView
}

type policyData struct {
	page
	ConfigPath string
	Summary    string
	Source     string
	Upstreams  []upstreamView
	Rules      []ruleView
	Message    string
	Error      string
}

func (s *Server) policyData() *policyData {
	cfg := s.opts.Config()
	d := &policyData{page: s.page("Policy", "policy")}
	if cfg == nil {
		d.Error = "no configuration loaded"
		return d
	}
	d.ConfigPath = cfg.Path
	d.Summary = cfg.Policy.Summary()
	if raw, err := os.ReadFile(cfg.Path); err == nil {
		d.Source = string(raw)
	} else if cfg.Path != "" {
		d.Source = "cannot read " + cfg.Path + ": " + err.Error()
	}
	for i := range cfg.Upstreams {
		u := &cfg.Upstreams[i]
		target := u.HTTP
		if target == "" {
			target = strings.Join(u.Stdio, " ")
		}
		prefix := ""
		if u.Prefix == nil || *u.Prefix {
			prefix = u.Name + cfg.PrefixSeparator
		}
		d.Upstreams = append(d.Upstreams, upstreamView{
			Name:      u.Name,
			Transport: u.Transport(),
			Target:    target,
			Prefix:    prefix,
			Timeout:   cfg.Timeout(u).String(),
		})
	}
	for _, r := range cfg.Policy.Rules {
		rv := ruleView{ID: r.ID, Tool: r.Tool, Action: r.Action, Reason: r.Reason}
		for _, c := range r.When {
			rv.When = append(rv.When, conditionView{Path: c.Path, Summary: matcherSummary(c.Matcher)})
		}
		d.Rules = append(d.Rules, rv)
	}
	return d
}

func (s *Server) handlePolicy(w http.ResponseWriter, r *http.Request) {
	s.render(w, "policy", s.policyData())
}

// handlePolicyValidate re-reads the config file and reports whether it parses,
// without touching the running proxy.
func (s *Server) handlePolicyValidate(w http.ResponseWriter, r *http.Request) {
	d := s.policyData()
	cfg := s.opts.Config()
	if cfg == nil || cfg.Path == "" {
		d.Error = "no configuration file to validate"
		s.renderPartial(w, "policy", "policy-status", d)
		return
	}
	fresh, err := config.Load(cfg.Path)
	if err != nil {
		d.Error = err.Error()
	} else {
		d.Message = fmt.Sprintf("%s is valid — %s, %d upstreams.",
			cfg.Path, fresh.Policy.Summary(), len(fresh.Upstreams))
	}
	s.renderPartial(w, "policy", "policy-status", d)
}

// handlePolicyReload swaps the policy into the running proxy. Upstreams are
// left alone: reloading must never drop a live connection.
func (s *Server) handlePolicyReload(w http.ResponseWriter, r *http.Request) {
	d := s.policyData()
	if s.opts.Reload == nil {
		d.Error = "this instance has no proxy to reload into (started with `agentgate ui`)"
		s.renderPartial(w, "policy", "policy-status", d)
		return
	}
	fresh, err := s.opts.Reload()
	if err != nil {
		d.Error = err.Error()
	} else {
		d.Message = "Policy reloaded — " + fresh.Policy.Summary() + ". Upstream connections were left untouched."
	}
	s.renderPartial(w, "policy", "policy-status", d)
}

type approvalView struct {
	proxy.PendingApproval
	Countdown string
}

type approvalsData struct {
	page
	Pending []approvalView
}

func (s *Server) approvalsData() *approvalsData {
	d := &approvalsData{page: s.page("Approvals", "approvals")}
	if s.opts.Approvals == nil {
		return d
	}
	for _, p := range s.opts.Approvals.Pending() {
		view := approvalView{PendingApproval: p}
		if !p.Expires.IsZero() {
			if left := time.Until(p.Expires); left > 0 {
				view.Countdown = left.Round(time.Second).String()
			} else {
				view.Countdown = "expired"
			}
		}
		d.Pending = append(d.Pending, view)
	}
	d.PendingCount = len(d.Pending)
	return d
}

func (s *Server) handleApprovals(w http.ResponseWriter, r *http.Request) {
	s.render(w, "approvals", s.approvalsData())
}

func (s *Server) handleApprovalsPartial(w http.ResponseWriter, r *http.Request) {
	s.renderPartial(w, "approvals", "approval-rows", s.approvalsData())
}

func (s *Server) handleApprovalDecide(w http.ResponseWriter, r *http.Request) {
	if s.opts.Approvals == nil {
		http.Error(w, "no approvals queue", http.StatusNotFound)
		return
	}
	choice := proxy.Choice(r.PathValue("verb"))
	switch choice {
	case proxy.ChoiceAllow, proxy.ChoiceAllowSession, proxy.ChoiceDeny:
	default:
		http.Error(w, "expected allow, allow-session or deny", http.StatusBadRequest)
		return
	}
	if !s.opts.Approvals.Resolve(r.PathValue("id"), choice, "the web UI") {
		s.log.Info("approval no longer pending", "id", r.PathValue("id"))
	}
	s.renderPartial(w, "approvals", "approval-rows", s.approvalsData())
}

// matcherSummary renders a matcher the way it reads in the config file.
func matcherSummary(m policy.Matcher) string {
	switch {
	case m.Equals != nil:
		return "equals " + jsonish(*m.Equals)
	case m.NotEquals != nil:
		return "not equals " + jsonish(*m.NotEquals)
	case m.Regex != nil:
		return "matches /" + *m.Regex + "/"
	case m.Prefix != nil:
		return "starts with " + jsonish(*m.Prefix)
	case m.NotPrefix != nil:
		return "does not start with " + jsonish(*m.NotPrefix)
	case m.In != nil:
		return "in " + jsonish(m.In)
	case m.Gt != nil && m.Lt != nil:
		return fmt.Sprintf("between %v and %v", *m.Gt, *m.Lt)
	case m.Gt != nil:
		return fmt.Sprintf("> %v", *m.Gt)
	case m.Lt != nil:
		return fmt.Sprintf("< %v", *m.Lt)
	case m.Exists != nil:
		if *m.Exists {
			return "is present"
		}
		return "is absent"
	}
	return "?"
}

func jsonish(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}

// handleFreeze throws the kill switch from the browser and sends the visitor
// back to where they were.
func (s *Server) handleFreeze(w http.ResponseWriter, r *http.Request) {
	if s.opts.Freeze == nil {
		http.Error(w, "this instance cannot freeze the gateway", http.StatusNotFound)
		return
	}
	reason := strings.TrimSpace(r.FormValue("reason"))
	if reason == "" {
		reason = "frozen from the web UI"
	}
	if err := s.opts.Freeze(reason, "the web UI"); err != nil {
		s.fail(w, err)
		return
	}
	s.log.Warn("gateway frozen from the web UI", "reason", reason)
	redirectBack(w, r)
}

func (s *Server) handleUnfreeze(w http.ResponseWriter, r *http.Request) {
	if s.opts.Unfreeze == nil {
		http.Error(w, "this instance cannot unfreeze the gateway", http.StatusNotFound)
		return
	}
	if err := s.opts.Unfreeze(); err != nil {
		s.fail(w, err)
		return
	}
	s.log.Warn("gateway unfrozen from the web UI")
	redirectBack(w, r)
}

// redirectBack returns to the page the form was on, or to the front page. Only
// same-site paths are honoured, so the referer cannot send anyone elsewhere.
func redirectBack(w http.ResponseWriter, r *http.Request) {
	to := "/"
	if ref := r.Header.Get("Referer"); ref != "" {
		if u, err := url.Parse(ref); err == nil && u.Path != "" && strings.HasPrefix(u.Path, "/") {
			to = u.Path
		}
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}
