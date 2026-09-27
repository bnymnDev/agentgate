package ui

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bnymnDev/agentgate/internal/audit"
	"github.com/bnymnDev/agentgate/internal/pinning"
	"github.com/bnymnDev/agentgate/internal/proxy"
)

// liveData is the live page: what is happening right now, across every
// session.
type liveData struct {
	page
	Calls []*audit.Call
	// Seq is the chain position the next poll continues from.
	Seq int64
	// Live are the sessions that have not ended, with the labels they have
	// picked up.
	Live []liveSession
	// Partial is set when rendering a poll response.
	Partial bool
}

type liveSession struct {
	*audit.Session
	Labels []string
}

const liveBacklog = 50

func (s *Server) handleLive(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	head, err := s.opts.Store.Head(ctx)
	if err != nil {
		s.fail(w, err)
		return
	}
	calls, err := s.opts.Store.ListCalls(ctx, audit.CallFilter{Newest: true, Limit: liveBacklog})
	if err != nil {
		s.fail(w, err)
		return
	}
	live, err := s.liveSessions(ctx)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, "live", &liveData{page: s.page("Live", "live"), Calls: calls, Seq: head.Seq, Live: live})
}

// handleLivePartial answers the page's poll: the calls recorded since seq,
// newest first, and a fresh poller that continues from the new head.
func (s *Server) handleLivePartial(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	seq, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	calls, err := s.opts.Store.ListCalls(ctx, audit.CallFilter{SeqAfter: &seq, Limit: 500})
	if err != nil {
		s.fail(w, err)
		return
	}
	for _, c := range calls {
		seq = max(seq, c.Seq)
	}
	// Newest first, like the rows already on the page.
	for i, j := 0, len(calls)-1; i < j; i, j = i+1, j-1 {
		calls[i], calls[j] = calls[j], calls[i]
	}
	live, err := s.liveSessions(ctx)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.renderPartial(w, "live", "live-poll", &liveData{page: s.page("Live", "live"), Calls: calls, Seq: seq, Live: live, Partial: true})
}

// liveSessions lists the sessions still open, recent ones only: a session
// whose process died without saying goodbye stays open in the log forever.
func (s *Server) liveSessions(ctx context.Context) ([]liveSession, error) {
	sessions, err := s.opts.Store.ListSessions(ctx, audit.SessionFilter{Since: time.Now().Add(-24 * time.Hour), Limit: 50})
	if err != nil {
		return nil, err
	}
	var out []liveSession
	for _, sess := range sessions {
		if sess.EndedAt != nil {
			continue
		}
		calls, err := s.opts.Store.ListCalls(ctx, audit.CallFilter{SessionID: sess.ID})
		if err != nil {
			return nil, err
		}
		var labels []string
		for _, c := range calls {
			labels = append(labels, c.Labels...)
		}
		out = append(out, liveSession{Session: sess, Labels: labels})
	}
	return out, nil
}

// toolsData is the tools page: every tool the servers offer and its standing
// with the lockfile and the definition scan.
type toolsData struct {
	page
	Reports  []proxy.ToolReport
	Offline  bool
	Pinned   []pinnedView
	Lockfile string
	Mode     string
	Scan     string
	Message  string
	Error    string
	CanTrust bool
}

type pinnedView struct {
	Upstream string
	Tool     string
	Pin      *pinning.Pin
}

func (s *Server) toolsData() *toolsData {
	cfg := s.opts.Config()
	d := &toolsData{page: s.page("Tools", "tools")}
	if cfg != nil {
		d.Lockfile, d.Mode, d.Scan = cfg.Pinning.Lockfile, cfg.Pinning.Mode, cfg.Pinning.Scan
	}
	if s.opts.Tools != nil {
		d.Reports = s.opts.Tools.ToolReports()
		d.CanTrust = cfg != nil && cfg.Pinning.Enabled()
		return d
	}
	// No proxy behind this UI: show what the lockfile holds.
	d.Offline = true
	if cfg == nil || !cfg.Pinning.Enabled() {
		return d
	}
	lock, err := pinning.Load(cfg.Pinning.Lockfile)
	if err != nil {
		d.Error = err.Error()
		return d
	}
	for up, u := range lock.Upstreams {
		for name, pin := range u.Tools {
			d.Pinned = append(d.Pinned, pinnedView{Upstream: up, Tool: name, Pin: pin})
		}
	}
	sort.Slice(d.Pinned, func(i, j int) bool {
		a, b := d.Pinned[i], d.Pinned[j]
		if a.Upstream != b.Upstream {
			return a.Upstream < b.Upstream
		}
		return a.Tool < b.Tool
	})
	return d
}

func (s *Server) handleTools(w http.ResponseWriter, _ *http.Request) {
	s.render(w, "tools", s.toolsData())
}

func (s *Server) handleTrust(w http.ResponseWriter, r *http.Request) {
	tool := strings.TrimSpace(r.FormValue("tool"))
	if s.opts.Tools == nil {
		http.Error(w, "no proxy runs behind this UI; use agentgate lock --trust", http.StatusNotFound)
		return
	}
	trusted, err := s.opts.Tools.Trust(r.Context(), tool)
	d := s.toolsData()
	switch {
	case errors.Is(err, proxy.ErrNoSuchTool):
		d.Error = err.Error()
	case err != nil:
		d.Error = "trusting " + tool + ": " + err.Error()
	default:
		names := make([]string, 0, len(trusted))
		for _, t := range trusted {
			names = append(names, t.Upstream+"."+t.Tool)
		}
		d.Message = "Trusted " + strings.Join(names, ", ") + " as offered now; the lockfile is updated."
		s.log.Warn("tool trusted from the web UI", "tools", strings.Join(names, ","))
	}
	s.render(w, "tools", d)
}
