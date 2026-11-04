package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"time"

	"github.com/bnymnDev/agentgate/internal/pinning"
	"github.com/bnymnDev/agentgate/internal/proxy"
)

// registryResult is one upstream compared with a registry.
type registryResult struct {
	Upstream    string               `json:"upstream"`
	Server      string               `json:"server,omitempty"`
	Version     string               `json:"version,omitempty"`
	Missing     bool                 `json:"missing,omitempty"`
	Error       string               `json:"error,omitempty"`
	Comparisons []pinning.Comparison `json:"comparisons,omitempty"`
}

// offered groups what each upstream offers now, by upstream.
func offered(reports []proxy.ToolReport) map[string][]pinning.Definition {
	out := map[string][]pinning.Definition{}
	for _, r := range reports {
		if r.Status == pinning.StatusRemoved {
			continue
		}
		out[r.Upstream] = append(out[r.Upstream], r.Current)
	}
	return out
}

// trustedNow groups what a human has trusted of each upstream: the pinned
// definition, whatever the server offers now.
func trustedNow(reports []proxy.ToolReport) (map[string][]pinning.Definition, []string) {
	out := map[string][]pinning.Definition{}
	var skipped []string
	for _, r := range reports {
		switch {
		case r.Status == pinning.StatusPinned && len(r.Findings) == 0:
			out[r.Upstream] = append(out[r.Upstream], r.Current)
		case r.Status == pinning.StatusChanged && r.Pinned != nil:
			out[r.Upstream] = append(out[r.Upstream], *r.Pinned)
		case r.Status == pinning.StatusRemoved:
		default:
			skipped = append(skipped, r.Upstream+"."+r.Tool)
		}
	}
	return out, skipped
}

func compareRegistry(ctx context.Context, source string, ups []proxy.UpstreamInfo, reports []proxy.ToolReport) []registryResult {
	defs := offered(reports)
	client := &http.Client{Timeout: 20 * time.Second}
	var out []registryResult
	for _, u := range ups {
		if !u.Connected {
			continue
		}
		r := registryResult{Upstream: u.Name, Server: u.Server, Version: u.Version}
		entry, err := pinning.LoadEntry(ctx, source, u.Server, u.Version, client)
		switch {
		case errors.Is(err, pinning.ErrNotInRegistry):
			r.Missing = true
		case err != nil:
			r.Error = err.Error()
		default:
			r.Comparisons = pinning.Compare(defs[u.Name], entry)
		}
		out = append(out, r)
	}
	return out
}

// registryClean reports whether everything the registry knows agrees.
// A server the registry has never seen is not a disagreement.
func registryClean(results []registryResult) bool {
	for _, r := range results {
		if r.Error != "" {
			return false
		}
		for _, c := range r.Comparisons {
			if c.Agree != pinning.AgreeSame {
				return false
			}
		}
	}
	return true
}

func printRegistry(w *lineWriter, source string, results []registryResult) {
	fmt.Fprintln(w.out)
	fmt.Fprintln(w.out, "registry  "+source)
	for _, r := range results {
		name := r.Server
		if r.Version != "" {
			name += " " + r.Version
		}
		switch {
		case r.Error != "":
			fmt.Fprintf(w.out, "  %s  %s: %s\n", w.paint(colourRed, "error"), r.Upstream, r.Error)
			continue
		case r.Missing:
			fmt.Fprintf(w.out, "  %s  %s (%s) is not in it; nothing to compare\n", w.dim("unknown"), r.Upstream, name)
			continue
		}
		counts := map[pinning.Agreement]int{}
		for _, c := range r.Comparisons {
			counts[c.Agree]++
		}
		if counts[pinning.AgreeSame] == len(r.Comparisons) {
			fmt.Fprintf(w.out, "  %s  %s (%s): all %d definitions are what the registry has\n", w.paint(colourGreen, "same"), r.Upstream, name, len(r.Comparisons))
			continue
		}
		fmt.Fprintf(w.out, "  %s  %s (%s): %d the same, %d different, %d only here, %d only in the registry\n",
			w.paint(colourRed, "differs"), r.Upstream, name, counts[pinning.AgreeSame], counts[pinning.AgreeDiffers],
			counts[pinning.AgreeOnlyHere], counts[pinning.AgreeOnlyThere])
		for _, c := range r.Comparisons {
			switch c.Agree {
			case pinning.AgreeDiffers:
				fmt.Fprintln(w.out, "    "+w.paint(colourRed, "different")+"  "+c.Ref)
				printDefinitionDiff(w, *c.There, *c.Here, "registry", "here")
			case pinning.AgreeOnlyHere:
				fmt.Fprintln(w.out, "    "+w.paint(colourYellow, "only here")+"  "+c.Ref+": the registry never saw it")
			case pinning.AgreeOnlyThere:
				fmt.Fprintln(w.out, "    "+w.dim("not offered")+"  "+c.Ref)
			}
		}
	}
}

func publishRegistry(out io.Writer, dir string, ups []proxy.UpstreamInfo, reports []proxy.ToolReport) error {
	trusted, skipped := trustedNow(reports)
	sort.Strings(skipped)
	for _, u := range ups {
		defs := trusted[u.Name]
		if !u.Connected || len(defs) == 0 {
			continue
		}
		file, err := pinning.Publish(dir, pinning.NewEntry(u.Server, u.Version, defs))
		if err != nil {
			fmt.Fprintf(out, "not published %s: %s\n", u.Name, err)
			continue
		}
		fmt.Fprintf(out, "published %s (%d definitions) to %s\n", u.Name, len(defs), file)
	}
	for _, s := range skipped {
		fmt.Fprintf(out, "left out %s: not trusted yet, agentgate lock --trust it first\n", s)
	}
	return nil
}
