package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/bnymnDev/agentgate/internal/audit"
	"github.com/bnymnDev/agentgate/internal/canary"
	"github.com/bnymnDev/agentgate/internal/config"
	"github.com/bnymnDev/agentgate/internal/install"
	"github.com/bnymnDev/agentgate/internal/killswitch"
	"github.com/bnymnDev/agentgate/internal/pinning"
	"github.com/bnymnDev/agentgate/internal/policy"
	"github.com/bnymnDev/agentgate/internal/proxy"
)

type checkLevel string

const (
	levelOK   checkLevel = "ok"
	levelWarn checkLevel = "warn"
	levelFail checkLevel = "fail"
	levelInfo checkLevel = "info"
)

type check struct {
	Level  checkLevel `json:"level"`
	Area   string     `json:"area"`
	Detail string     `json:"detail"`
	Hint   string     `json:"hint,omitempty"`
}

func newDoctorCmd(g *globals) *cobra.Command {
	var (
		offline bool
		asJSON  bool
	)
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check that everything agentgate depends on is in order",
		Long: `Check the config, the audit log and its hash chain, every upstream server
(it is started and asked for its tools, unless --offline), the kill switch,
the policy, pinning, canaries, the approval channels, telemetry and the hosts
agentgate is installed into — and say what to do about anything that is off.

Exits 1 when a check fails.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var checks []check
			add := func(level checkLevel, area, detail, hint string) {
				checks = append(checks, check{level, area, detail, hint})
			}
			cfg := doctorConfig(g, add)
			if cfg != nil {
				doctorAudit(cmd.Context(), cfg, add)
				doctorUpstreams(cmd.Context(), g, cfg, offline, add)
				doctorPolicy(cfg, add)
				doctorPinning(cfg, add)
				doctorCanaries(cfg, add)
				doctorApprovals(cmd.Context(), cfg, offline, add)
				doctorTelemetry(cfg, add)
			}
			doctorHosts(add)

			if asJSON {
				if err := writeJSON(cmd.OutOrStdout(), checks); err != nil {
					return err
				}
			} else {
				printChecks(cmd.OutOrStdout(), checks)
			}
			for _, c := range checks {
				if c.Level == levelFail {
					return errExitDenied
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&offline, "offline", false, "do not start the upstream servers or reach out to the network")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the checks as JSON")
	return cmd
}

func printChecks(out io.Writer, checks []check) {
	fmt.Fprintf(out, "agentgate %s doctor\n\n", version())
	var fails, warns int
	for _, c := range checks {
		fmt.Fprintf(out, "  %-4s  %-10s %s\n", c.Level, c.Area, c.Detail)
		if c.Hint != "" {
			fmt.Fprintf(out, "  %-4s  %-10s %s\n", "", "", "→ "+c.Hint)
		}
		switch c.Level {
		case levelFail:
			fails++
		case levelWarn:
			warns++
		}
	}
	fmt.Fprintln(out)
	switch {
	case fails > 0:
		fmt.Fprintf(out, "%d problem(s), %d warning(s)\n", fails, warns)
	case warns > 0:
		fmt.Fprintf(out, "working, with %d warning(s)\n", warns)
	default:
		fmt.Fprintln(out, "all good")
	}
}

type addFunc func(level checkLevel, area, detail, hint string)

func doctorConfig(g *globals, add addFunc) *config.Config {
	path, err := g.configFile()
	if err != nil {
		add(levelFail, "config", err.Error(), "agentgate init writes one for each MCP host")
		return nil
	}
	cfg, err := config.Load(path)
	if err != nil {
		add(levelFail, "config", strings.ReplaceAll(err.Error(), "\n", "; "), "agentgate policy validate "+path+" lists every problem")
		return nil
	}
	add(levelOK, "config", path, "")
	return cfg
}

func doctorAudit(ctx context.Context, cfg *config.Config, add addFunc) {
	if !cfg.AuditEnabled() {
		add(levelWarn, "audit", "auditing is disabled", "without it there is no record, no replay and no stats")
		return
	}
	if _, err := os.Stat(cfg.Audit.Path); err != nil {
		dir := filepath.Dir(cfg.Audit.Path)
		if err := dirWritable(dir); err != nil {
			add(levelFail, "audit", fmt.Sprintf("%s cannot be created: %v", cfg.Audit.Path, err), "")
			return
		}
		add(levelInfo, "audit", cfg.Audit.Path+" does not exist yet; it is created on the first run", "")
		return
	}
	store, err := audit.Open(ctx, audit.Options{Path: cfg.Audit.Path, ReadOnly: true})
	if err != nil {
		add(levelFail, "audit", err.Error(), "")
		return
	}
	defer closeStore(store)
	version, _ := store.SchemaVersion(ctx)
	stats, _ := store.Stats(ctx, time.Time{})
	calls := 0
	if stats != nil {
		calls = stats.Calls
	}
	report, err := store.Verify(ctx, nil)
	switch {
	case err != nil:
		add(levelFail, "audit", "cannot verify the hash chain: "+err.Error(), "")
	case !report.OK():
		add(levelFail, "audit", fmt.Sprintf("%s: the hash chain is broken in %d place(s)", cfg.Audit.Path, len(report.Problems)), "agentgate verify shows where")
	default:
		add(levelOK, "audit", fmt.Sprintf("%s (schema %s, %d calls, chain intact up to %d)", cfg.Audit.Path, version, calls, report.Head.Seq), "")
	}
	if st, frozen := killswitch.Status(cfg.FreezeFile()); frozen {
		add(levelWarn, "freeze", fmt.Sprintf("FROZEN since %s by %s: %s", st.At.Local().Format(time.DateTime), st.By, st.Reason), "agentgate unfreeze, once you have looked")
	}
}

func dirWritable(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".doctor-*")
	if err != nil {
		return err
	}
	name := f.Name()
	_ = f.Close()
	return os.Remove(name)
}

func doctorUpstreams(ctx context.Context, g *globals, cfg *config.Config, offline bool, add addFunc) {
	for i := range cfg.Upstreams {
		u := &cfg.Upstreams[i]
		if u.Transport() == "stdio" {
			if _, err := exec.LookPath(u.Stdio[0]); err != nil {
				add(levelFail, "upstream", fmt.Sprintf("%s: %s: not found", u.Name, u.Stdio[0]), "install it, or give its absolute path in stdio:")
				continue
			}
		}
		if offline {
			add(levelInfo, "upstream", fmt.Sprintf("%s: %s, not started (--offline)", u.Name, u.Transport()), "")
			continue
		}
		single := *cfg
		single.Upstreams = []config.Upstream{*u}
		p, err := proxy.New(proxy.Options{Config: &single, Logger: g.quietLogger(), DownstreamTransport: "doctor", Pinning: proxy.PinningInspect})
		if err != nil {
			add(levelFail, "upstream", fmt.Sprintf("%s: %v", u.Name, err), "")
			continue
		}
		connectCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		err = p.Connect(connectCtx)
		cancel()
		if err != nil {
			_ = p.Close()
			add(levelFail, "upstream", fmt.Sprintf("%s: %v", u.Name, oneLine(err)), "run the command by hand to see why it does not start")
			continue
		}
		tools := len(p.Tools())
		_ = p.Close()
		add(levelOK, "upstream", fmt.Sprintf("%s: %d tools over %s", u.Name, tools, u.Transport()), "")
	}
}

func oneLine(err error) string {
	s := err.Error()
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}

func doctorPolicy(cfg *config.Config, add addFunc) {
	add(levelOK, "policy", cfg.Policy.Summary(), "")
	if cfg.Policy.IsShadow() {
		add(levelWarn, "policy", "shadow mode: decisions are recorded, nothing is blocked", "set policy.mode: enforce when agentgate stats shows it would block the right things")
	}
	warns := 0
	for _, f := range policy.Lint(&cfg.Policy, policy.LintContext{ApprovalMode: cfg.Approval.Mode}) {
		if f.Severity == policy.SeverityWarn {
			warns++
		}
	}
	if warns > 0 {
		add(levelWarn, "policy", fmt.Sprintf("%d lint warning(s)", warns), "agentgate policy lint")
	}
}

func doctorPinning(cfg *config.Config, add addFunc) {
	if !cfg.Pinning.Enabled() {
		add(levelWarn, "pinning", "off: a server can change what its tools say without anyone noticing", "set pinning.mode: warn")
		return
	}
	lock, err := pinning.Load(cfg.Pinning.Lockfile)
	if err != nil {
		add(levelFail, "pinning", err.Error(), "fix or delete the lockfile; it is rebuilt on first use")
		return
	}
	var pinned, drifted int
	for _, u := range lock.Upstreams {
		for _, pin := range u.Tools {
			pinned++
			if pin.Drift != nil {
				drifted++
			}
		}
	}
	switch {
	case pinned == 0:
		add(levelInfo, "pinning", fmt.Sprintf("%s mode, nothing pinned yet; tools are pinned on first use", cfg.Pinning.Mode), "")
	case drifted > 0:
		add(levelWarn, "pinning", fmt.Sprintf("%d of %d pinned tools changed since they were pinned", drifted, pinned), "agentgate lock shows what changed")
	default:
		add(levelOK, "pinning", fmt.Sprintf("%s mode, scan %s, %d tools pinned, no drift", cfg.Pinning.Mode, cfg.Pinning.Scan, pinned), "")
	}
}

func doctorCanaries(cfg *config.Config, add addFunc) {
	store, err := canary.Open(cfg.Canaries.Path)
	if err != nil {
		add(levelFail, "canaries", err.Error(), "")
		return
	}
	list := store.List()
	if len(list) == 0 {
		add(levelInfo, "canaries", "none planted", "agentgate canary new --write <path> plants a fake credential that catches exfiltration")
		return
	}
	missing := 0
	for _, c := range list {
		if c.File != "" {
			if _, err := os.Stat(c.File); errors.Is(err, os.ErrNotExist) {
				missing++
			}
		}
	}
	detail := fmt.Sprintf("%d planted, a leak is %sed", len(list), map[string]string{"deny": "deni", "freeze": "frozen and deni"}[cfg.Canaries.Action])
	if missing > 0 {
		add(levelWarn, "canaries", fmt.Sprintf("%s; %d decoy file(s) are gone", detail, missing), "agentgate canary list")
		return
	}
	add(levelOK, "canaries", detail, "")
}

func doctorApprovals(ctx context.Context, cfg *config.Config, offline bool, add addFunc) {
	var channels []string
	if proxy.NewTTYApprover() != nil {
		channels = append(channels, "terminal")
	}
	if n := cfg.Approval.Ntfy; n != nil {
		channels = append(channels, "phone ("+n.Server+")")
		if !offline {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(n.Server, "/")+"/v1/health", nil)
			if err == nil {
				resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
				if err != nil {
					add(levelWarn, "approvals", "the ntfy server cannot be reached: "+oneLine(err), "")
				} else {
					_ = resp.Body.Close()
				}
			}
		}
	}
	mode := cfg.Approval.Mode
	switch {
	case mode == "deny":
		add(levelInfo, "approvals", "mode deny: every ask is denied", "")
	case len(channels) == 0:
		add(levelWarn, "approvals", "mode "+mode+": no channel here to ask on besides the web UI (run with --ui)", "set approval.ntfy to approve on your phone")
	default:
		add(levelOK, "approvals", fmt.Sprintf("mode %s: %s, plus the web UI when it runs", mode, strings.Join(channels, ", ")), "")
	}
}

func doctorTelemetry(cfg *config.Config, add addFunc) {
	endpoint := cfg.Telemetry.OTLP.Endpoint
	if endpoint == "" {
		endpoint = os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	}
	if endpoint == "" {
		endpoint = os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
	}
	if endpoint != "" {
		add(levelOK, "telemetry", "spans go to "+endpoint, "")
	}
}

func doctorHosts(add addFunc) {
	env, err := install.DefaultEnv()
	if err != nil {
		return
	}
	home, err := agentgateHome("")
	if err != nil {
		return
	}
	manifest, err := install.LoadManifest(home)
	if err != nil {
		add(levelWarn, "hosts", err.Error(), "")
		return
	}
	cands, err := install.Scan(env, manifest)
	if err != nil {
		add(levelWarn, "hosts", err.Error(), "")
		return
	}
	for _, c := range cands {
		switch c.Status {
		case install.StatusInstalled:
			add(levelOK, "hosts", c.Host.Title+": behind agentgate", "")
		case install.StatusReady:
			add(levelInfo, "hosts", fmt.Sprintf("%s: %d server(s) not behind agentgate", c.Host.Title, len(c.Wrapped)), "agentgate init --host "+c.Host.Name)
		}
	}
}
