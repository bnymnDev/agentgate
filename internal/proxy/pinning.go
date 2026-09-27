package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/bnymnDev/agentgate/internal/audit"
	"github.com/bnymnDev/agentgate/internal/config"
	"github.com/bnymnDev/agentgate/internal/pinning"
	"github.com/bnymnDev/agentgate/internal/policy"
)

// PinningMode says what the proxy may do with the lockfile.
type PinningMode int

const (
	// PinningLive follows the config: tools are pinned on first sight,
	// drift is recorded and reported, and tools are held back as configured.
	PinningLive PinningMode = iota
	// PinningInspect compares and reports but never writes the lockfile and
	// never holds a tool back. `agentgate lock` and replay use it.
	PinningInspect
)

// ToolReport is a tool's standing with the lockfile and the definition scan.
type ToolReport struct {
	pinning.Report
	// Exposed is the name the host sees; empty for a tool that was removed.
	Exposed string `json:"exposed,omitempty"`
	// PinnedNow is set when the tool was pinned on this sight, on first use.
	PinnedNow bool `json:"pinned_now,omitempty"`
	// Quarantined is set when the tool is hidden from the host. Reason says
	// why it is, or why it would be when the proxy only inspects.
	Quarantined bool   `json:"quarantined,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

// offeredTool is one tool as an upstream listed it during a refresh.
type offeredTool struct {
	upstream string
	exposed  string
	def      pinning.Definition
}

// fileStamp is enough of a file's metadata to notice that it changed.
type fileStamp struct {
	mod  time.Time
	size int64
}

func stampOf(path string) fileStamp {
	info, err := os.Stat(path)
	if err != nil {
		return fileStamp{}
	}
	return fileStamp{mod: info.ModTime(), size: info.Size()}
}

// lockfile returns the loaded lockfile, loading it on first use. It is
// called with lockMu held.
func (p *Proxy) lockfile(cfg *config.Config) *pinning.Lockfile {
	if p.lock != nil {
		return p.lock
	}
	if !cfg.Pinning.Enabled() {
		p.lock = &pinning.Lockfile{Version: 1, Upstreams: map[string]*pinning.Upstream{}}
		return p.lock
	}
	lock, err := pinning.Load(cfg.Pinning.Lockfile)
	if err != nil {
		// A lockfile that cannot be read must not silently become an empty
		// one: that would re-pin whatever the servers offer right now.
		p.log.Error("cannot read the lockfile; pinning is suspended until it is fixed", "path", cfg.Pinning.Lockfile, "error", err)
		return nil
	}
	p.lock = lock
	p.lockStamp = stampOf(cfg.Pinning.Lockfile)
	return lock
}

// checkPins compares what the upstreams offer with the lockfile, scans every
// definition, pins what is new if the mode allows, and returns the tools to
// hold back, with the reason, and every tool's report.
func (p *Proxy) checkPins(cfg *config.Config, offered []offeredTool) (map[string]string, []ToolReport) {
	pin := &cfg.Pinning
	if !pin.Enabled() && !pin.Scans() {
		return nil, nil
	}
	live := p.pinMode == PinningLive

	p.lockMu.Lock()
	defer p.lockMu.Unlock()
	lock := p.lockfile(cfg)
	if lock == nil {
		return nil, nil
	}

	byUpstream := map[string][]offeredTool{}
	var upstreams []string
	for _, t := range offered {
		if _, ok := byUpstream[t.upstream]; !ok {
			upstreams = append(upstreams, t.upstream)
		}
		byUpstream[t.upstream] = append(byUpstream[t.upstream], t)
	}
	sort.Strings(upstreams)

	now := time.Now()
	dirty := false
	held := map[string]string{}
	var reports []ToolReport
	for _, up := range upstreams {
		tools := byUpstream[up]
		defs := make([]pinning.Definition, 0, len(tools))
		exposed := map[string]string{}
		for _, t := range tools {
			defs = append(defs, t.def)
			exposed[t.def.Name] = t.exposed
		}
		var others []pinning.OtherTool
		for _, t := range offered {
			if t.upstream != up {
				others = append(others, pinning.OtherTool{Upstream: t.upstream, Name: t.def.Name})
			}
		}
		for _, r := range lock.Check(up, defs, others) {
			tr := ToolReport{Report: r, Exposed: exposed[r.Tool]}
			reason := ""
			switch r.Status {
			case pinning.StatusUnpinned:
				if pin.Enabled() && live {
					lock.Pin(up, r.Current, nil, now)
					tr.PinnedNow, dirty = true, true
				}
			case pinning.StatusNew:
				switch {
				case pin.Enforced():
					reason = "it is new since the server was pinned, and pinning is enforced"
				case live:
					lock.Pin(up, r.Current, nil, now)
					tr.PinnedNow, dirty = true, true
				}
				if live {
					p.announceDrift(up, tr, "offers a new tool", reason)
				}
			case pinning.StatusChanged:
				if pin.Enforced() {
					reason = "its definition changed since it was pinned"
				}
				if live && lock.NoteDrift(r, now) {
					dirty = true
					p.announceDrift(up, tr, "changed a pinned tool: "+changeSummary(*r.Pinned, r.Current), reason)
				}
			case pinning.StatusRemoved:
				reports = append(reports, tr)
				continue
			}
			if len(r.Findings) > 0 && pin.Scans() {
				if pin.Quarantines() && reason == "" {
					reason = "its definition " + r.Findings[0].Detail
				}
				if live {
					p.announceFindings(up, tr, reason)
				}
			}
			tr.Reason = reason
			if reason != "" && live {
				held[tr.Exposed] = reason
				tr.Quarantined = true
			}
			reports = append(reports, tr)
		}
	}
	if dirty && live && pin.Enabled() {
		if err := lock.Save(); err != nil {
			p.log.Warn("cannot write the lockfile; pins are kept in memory until the next start", "path", lock.Path(), "error", err)
		} else {
			p.lockStamp = stampOf(lock.Path())
		}
	}
	return held, reports
}

// announceDrift logs and notifies a change to what a server offers.
func (p *Proxy) announceDrift(upstream string, tr ToolReport, what, heldReason string) {
	key := "drift\x00" + upstream + "\x00" + tr.Tool + "\x00" + tr.Current.Hash()
	if !p.firstAnnouncement(key) {
		return
	}
	msg := fmt.Sprintf("%s %s: %s", upstream, what, tr.Tool)
	if heldReason != "" {
		msg += ". The tool is hidden from the host until you trust it: agentgate lock --trust " + tr.Upstream + "." + tr.Tool
	}
	p.log.Error("tool drift", "upstream", upstream, "tool", tr.Tool, "status", string(tr.Status), "held", heldReason != "")
	p.notify.emit(Event{
		Event:    config.EventDrift,
		Upstream: upstream,
		Tool:     tr.Exposed,
		Decision: driftDecision(heldReason, tr.Status),
		Message:  msg,
	})
}

// announceFindings logs and notifies what the definition scan found.
func (p *Proxy) announceFindings(upstream string, tr ToolReport, heldReason string) {
	key := "scan\x00" + upstream + "\x00" + tr.Tool + "\x00" + tr.Current.Hash()
	if !p.firstAnnouncement(key) {
		return
	}
	var lines []string
	for _, f := range tr.Findings {
		line := f.Where + ": " + f.Detail
		if f.Excerpt != "" {
			line += fmt.Sprintf(" (%q)", truncateRunes(f.Excerpt, 160))
		}
		lines = append(lines, line)
	}
	msg := fmt.Sprintf("%s's tool %s looks poisoned:\n%s", upstream, tr.Tool, strings.Join(lines, "\n"))
	if heldReason != "" {
		msg += "\nIt is hidden from the host until you trust it: agentgate lock --trust " + tr.Upstream + "." + tr.Tool
	}
	p.log.Error("tool definition flagged", "upstream", upstream, "tool", tr.Tool, "findings", len(tr.Findings), "held", heldReason != "")
	p.notify.emit(Event{
		Event:    config.EventDrift,
		Upstream: upstream,
		Tool:     tr.Exposed,
		Decision: driftDecision(heldReason, tr.Status),
		Message:  msg,
	})
}

func driftDecision(heldReason string, status pinning.Status) policy.Decision {
	if heldReason != "" {
		return policy.Decision{Action: policy.ActionDeny, RuleID: policy.RuleQuarantine, Reason: heldReason}
	}
	return policy.Decision{Action: policy.ActionAllow, Reason: "tool " + string(status) + "; pinning is not enforced"}
}

// firstAnnouncement reports whether key has not been announced by this
// process yet, and remembers it.
func (p *Proxy) firstAnnouncement(key string) bool {
	p.catalog.mu.Lock()
	defer p.catalog.mu.Unlock()
	if p.catalog.announced == nil {
		p.catalog.announced = map[string]bool{}
	}
	if p.catalog.announced[key] {
		return false
	}
	p.catalog.announced[key] = true
	return true
}

// changeSummary says in a few words what differs between two definitions.
func changeSummary(before, after pinning.Definition) string {
	var parts []string
	if before.Description != after.Description {
		parts = append(parts, fmt.Sprintf("description (%d → %d characters)", len(before.Description), len(after.Description)))
	}
	if before.Title != after.Title {
		parts = append(parts, "title")
	}
	if string(before.InputSchema) != string(after.InputSchema) {
		parts = append(parts, "input schema")
	}
	if string(before.OutputSchema) != string(after.OutputSchema) {
		parts = append(parts, "output schema")
	}
	if string(before.Annotations) != string(after.Annotations) {
		parts = append(parts, "annotations")
	}
	if len(parts) == 0 {
		return "definition"
	}
	return strings.Join(parts, ", ")
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// ToolReports returns every tool's standing with the lockfile and the scan,
// as of the last refresh.
func (p *Proxy) ToolReports() []ToolReport {
	p.catalog.mu.Lock()
	defer p.catalog.mu.Unlock()
	out := append([]ToolReport(nil), p.catalog.reports...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Upstream != out[j].Upstream {
			return out[i].Upstream < out[j].Upstream
		}
		return out[i].Tool < out[j].Tool
	})
	return out
}

// ErrNoSuchTool is returned by Trust for a tool the last refresh did not see.
var ErrNoSuchTool = errors.New("no such tool")

// Trust pins a tool as it is offered now, accepting whatever the scan found
// in it, writes the lockfile and refreshes the catalog so a tool that was
// held back reaches the host. tool is "upstream.tool" or the exposed name;
// "*" trusts everything that is not already pinned and clean.
func (p *Proxy) Trust(ctx context.Context, tool string) ([]ToolReport, error) {
	cfg := p.Config()
	if !cfg.Pinning.Enabled() {
		return nil, errors.New("pinning is off in the config; there is no lockfile to trust anything into")
	}
	var picked []ToolReport
	for _, r := range p.ToolReports() {
		clean := r.Status == pinning.StatusPinned && len(r.Findings) == 0
		switch {
		case tool == "*" && !clean:
		case tool == r.Upstream+"."+r.Tool, tool != "" && tool == r.Exposed:
		default:
			continue
		}
		picked = append(picked, r)
	}
	if len(picked) == 0 {
		if tool == "*" {
			return nil, nil
		}
		return nil, fmt.Errorf("%s: %w; agentgate lock lists the tools", tool, ErrNoSuchTool)
	}
	p.lockMu.Lock()
	lock := p.lockfile(cfg)
	if lock == nil {
		p.lockMu.Unlock()
		return nil, errors.New("the lockfile cannot be read; fix or remove it first")
	}
	// Someone else may have written the file since it was read.
	if fresh, err := pinning.Load(lock.Path()); err == nil {
		lock = fresh
		p.lock = fresh
	}
	now := time.Now()
	for _, r := range picked {
		lock.Trust(r.Report, now)
	}
	err := lock.Save()
	if err == nil {
		p.lockStamp = stampOf(lock.Path())
	}
	p.lockMu.Unlock()
	if err != nil {
		return nil, err
	}
	for _, r := range picked {
		p.log.Info("tool trusted", "upstream", r.Upstream, "tool", r.Tool, "was", string(r.Status), "findings", len(r.Findings))
	}
	return picked, p.Refresh(ctx)
}

// watchLockfile re-reads the lockfile when something other than this process
// changes it — `agentgate lock --trust` in another terminal, a git checkout —
// and refreshes the catalog, so a trusted tool shows up without a restart.
func (p *Proxy) watchLockfile(interval time.Duration) {
	cfg := p.Config()
	if !cfg.Pinning.Enabled() || p.pinMode != PinningLive {
		return
	}
	path := cfg.Pinning.Lockfile
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-p.done:
				return
			case <-t.C:
			}
			now := stampOf(path)
			p.lockMu.Lock()
			changed := now != p.lockStamp
			if changed {
				lock, err := pinning.Load(path)
				if err != nil {
					p.log.Warn("the lockfile changed but cannot be read", "path", path, "error", err)
					p.lockStamp = now
					p.lockMu.Unlock()
					continue
				}
				p.lock, p.lockStamp = lock, now
			}
			p.lockMu.Unlock()
			if changed {
				p.log.Info("lockfile changed on disk; checking the tools again", "path", path)
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				if err := p.Refresh(ctx); err != nil {
					p.log.Warn("refreshing catalog", "error", err)
				}
				cancel()
			}
		}
	}()
}

// onQuarantinedCall answers a tools/call for a tool that is held back. The
// host should not know the name, since the tool is not listed, but a host
// with a stale list, or an agent that read the name somewhere, may still ask.
func (p *Proxy) onQuarantinedCall(req mcp.Request) (*mcp.CallToolResult, bool) {
	call, ok := req.(*mcp.CallToolRequest)
	if !ok || call.Params == nil {
		return nil, false
	}
	p.catalog.mu.Lock()
	reason, held := p.catalog.quarantined[call.Params.Name]
	p.catalog.mu.Unlock()
	if !held {
		return nil, false
	}
	st := p.state(call)
	now := time.Now()
	decision := policy.Decision{
		Action: policy.ActionDeny,
		RuleID: policy.RuleQuarantine,
		Reason: "this tool is quarantined: " + reason + ". A human has to look at it first (agentgate lock)",
	}
	result := deniedResult(decision)
	upstream, _, _ := p.Config().SplitTool(call.Params.Name)
	p.store.RecordCall(&audit.Call{
		ID: audit.NewID(), SessionID: st.id, TS: now, Upstream: upstream, Tool: call.Params.Name,
		Args: call.Params.Arguments, Decision: decision.Action, RuleID: decision.RuleID, Reason: decision.Reason,
		Result: marshalResult(result), IsError: true, CatalogHash: p.catalogHash(),
	})
	p.log.Warn("call to a quarantined tool denied", "session", st.id, "tool", call.Params.Name)
	p.notify.emit(Event{
		Event: config.EventDeny, At: now, SessionID: st.id, Host: hostLabel(st),
		Upstream: upstream, Tool: call.Params.Name, Decision: decision, Args: call.Params.Arguments,
	})
	return result, true
}

// definitionOf turns a listed tool into what is pinned.
func definitionOf(t *mcp.Tool) (pinning.Definition, error) {
	raw, err := json.Marshal(t)
	if err != nil {
		return pinning.Definition{}, err
	}
	return pinning.DefinitionFromJSON(raw)
}
