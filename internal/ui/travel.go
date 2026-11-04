package ui

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/bnymnDev/agentgate/internal/audit"
	"github.com/bnymnDev/agentgate/internal/policy"
	"github.com/bnymnDev/agentgate/internal/replay"
)

type travelData struct {
	page
	Session *audit.Session
	Entries []*replay.Entry
	Current *replay.Entry
	Step    int
	Number  int
	Last    int
	Prev    int
	Next    int
	Changed int
}

func (s *Server) handleTravel(w http.ResponseWriter, r *http.Request) {
	sess, err := s.opts.Store.GetSession(r.Context(), r.PathValue("id"))
	if errors.Is(err, audit.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	calls, err := s.opts.Store.ListCalls(r.Context(), audit.CallFilter{SessionID: sess.ID, Limit: 100000})
	if err != nil {
		s.fail(w, err)
		return
	}
	var rep *replay.Report
	if s.opts.Replay != nil {
		rep, err = s.opts.Replay(r.Context(), sess, calls)
	} else {
		cfg := s.opts.Config()
		rep, err = replay.Run(r.Context(), sess.ID, calls, replay.Options{
			Policy: &cfg.Policy, Host: policy.Host{Name: sess.HostName, Version: sess.HostVersion}})
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	d := &travelData{page: s.page("Time travel "+sess.ID, "sessions"), Session: sess, Entries: rep.Entries}
	d.Changed = len(rep.Changed())
	if n := len(rep.Entries); n > 0 {
		d.Last = n - 1
		d.Step = d.Last
		if v, err := strconv.Atoi(r.URL.Query().Get("step")); err == nil {
			d.Step = min(max(v, 0), d.Last)
		}
		d.Current = rep.Entries[d.Step]
		d.Number = d.Step + 1
		d.Prev, d.Next = max(d.Step-1, 0), min(d.Step+1, d.Last)
	}
	s.render(w, "travel", d)
}
