package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/bnymnDev/agentgate/internal/install"
)

func agentgateHome(dir string) (string, error) {
	if dir != "" {
		return filepath.Abs(dir)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".agentgate"), nil
}

func newInitCmd() *cobra.Command {
	var (
		hosts []string
		yes   bool
		dir   string
	)
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Put agentgate in front of the MCP servers your hosts already use",
		Long: `Find the MCP hosts on this machine — Claude Desktop, Claude Code, Cursor,
Windsurf, VS Code, Gemini CLI — and put agentgate in front of the servers
they are configured with.

For each host, init writes ~/.agentgate/<host>.yaml with the host's servers as
upstreams, in shadow mode (everything is recorded, nothing is blocked) with the
baseline, secrets and lethal-trifecta packs, and replaces those servers in the
host's config with a single entry that runs agentgate. Nothing else in the
host's config changes, and the original entries are kept, so

	agentgate uninstall

puts everything back. Without --yes, init only shows what it would do.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()
			env, err := install.DefaultEnv()
			if err != nil {
				return err
			}
			home, err := agentgateHome(dir)
			if err != nil {
				return err
			}
			manifest, err := install.LoadManifest(home)
			if err != nil {
				return err
			}
			cands, err := install.Scan(env, manifest)
			if err != nil {
				return err
			}
			picked, err := pickHosts(cands, hosts)
			if err != nil {
				return err
			}
			printCandidates(out, cands)
			if len(picked) == 0 {
				fmt.Fprintln(out, "\nNothing to do: no host with MCP servers that agentgate is not already in front of.")
				return nil
			}
			if !yes {
				fmt.Fprintln(out, "\nagentgate init --yes would:")
				for _, c := range picked {
					fmt.Fprintf(out, "  - write %s for %s, with its servers as upstreams, in shadow mode,\n",
						filepath.Join(home, c.Host.Name+".yaml"), c.Host.Title)
				}
				fmt.Fprintln(out, "  - replace those servers in the host's config with one entry that runs agentgate,")
				fmt.Fprintf(out, "  - keep the originals in %s so agentgate uninstall can put them back.\n", filepath.Join(home, "installed.json"))
				return nil
			}

			binary, err := executable()
			if err != nil {
				return err
			}
			opts := install.Options{Dir: home, Binary: binary, Now: time.Now()}
			fmt.Fprintln(out)
			for _, c := range picked {
				inst, err := install.Apply(c, manifest, opts)
				if err != nil {
					return fmt.Errorf("%s: %w", c.Host.Name, err)
				}
				fmt.Fprintf(out, "%s: %d server(s) now behind agentgate, config %s\n", c.Host.Title, len(c.Wrapped), inst.Config)
			}
			fmt.Fprintln(out, "\nRestart the host(s) so they start agentgate. Then watch what the agent does:")
			fmt.Fprintln(out, "  agentgate tail -c "+filepath.Join(home, picked[0].Host.Name+".yaml"))
			fmt.Fprintln(out, "  agentgate stats -c "+filepath.Join(home, picked[0].Host.Name+".yaml"))
			fmt.Fprintln(out, "The policy is in shadow mode; switch it to enforce when you are happy with what it would block.")
			return nil
		},
	}
	cmd.Flags().StringArrayVar(&hosts, "host", nil, "only this host (repeatable): "+strings.Join(hostNames(), ", "))
	cmd.Flags().BoolVar(&yes, "yes", false, "make the changes instead of showing them")
	cmd.Flags().StringVar(&dir, "dir", "", "where agentgate keeps its configs and the manifest (default ~/.agentgate)")
	return cmd
}

func newUninstallCmd() *cobra.Command {
	var dir string
	cmd := &cobra.Command{
		Use:   "uninstall [host...]",
		Short: "Take agentgate out from in front of a host's MCP servers",
		Long: `Put back the MCP servers agentgate init moved behind agentgate, in each
host's own config. Servers added to the host since then are kept. The
agentgate configs and the audit log stay where they are.

Without a host name, every host agentgate was installed into is restored.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			home, err := agentgateHome(dir)
			if err != nil {
				return err
			}
			manifest, err := install.LoadManifest(home)
			if err != nil {
				return err
			}
			names := args
			if len(names) == 0 {
				for name := range manifest.Hosts {
					names = append(names, name)
				}
			}
			if len(names) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "agentgate init has not installed into any host")
				return nil
			}
			var errs []error
			for _, name := range names {
				inst, err := install.Uninstall(name, manifest)
				if err != nil {
					errs = append(errs, err)
					continue
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s: servers restored in %s (the agentgate config %s is left in place)\n",
					inst.Host.Title, inst.Host.Path, inst.Config)
			}
			if len(errs) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "Restart the host(s) to pick the change up.")
			}
			return errors.Join(errs...)
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "", "where agentgate keeps its configs and the manifest (default ~/.agentgate)")
	return cmd
}

func pickHosts(cands []install.Candidate, names []string) ([]install.Candidate, error) {
	if len(names) == 0 {
		var out []install.Candidate
		for _, c := range cands {
			if c.Status == install.StatusReady {
				out = append(out, c)
			}
		}
		return out, nil
	}
	var out []install.Candidate
	for _, name := range names {
		found := false
		for _, c := range cands {
			if c.Host.Name != name {
				continue
			}
			found = true
			if c.Status != install.StatusReady {
				return nil, fmt.Errorf("%s: %s", name, c.Status)
			}
			out = append(out, c)
		}
		if !found {
			return nil, fmt.Errorf("unknown host %q, use one of %s", name, strings.Join(hostNames(), ", "))
		}
	}
	return out, nil
}

func printCandidates(out io.Writer, cands []install.Candidate) {
	t := newTable(out, "HOST", "STATUS", "SERVERS", "CONFIG")
	for _, c := range cands {
		if c.Status == install.StatusAbsent {
			continue
		}
		var names []string
		for _, s := range c.Wrapped {
			names = append(names, s.Name)
		}
		t.row(c.Host.Name, c.Status, orDash(truncate(strings.Join(names, ", "), 40)), c.Host.Path)
	}
	t.flush()
}

func hostNames() []string {
	var out []string
	for _, h := range install.Hosts(install.Env{}) {
		out = append(out, h.Name)
	}
	return out
}

// executable is the absolute path the host should run. A binary from `go run`
// lives in a temporary directory that is gone when the command exits.
func executable() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	}
	if strings.Contains(path, string(filepath.Separator)+"go-build") {
		return "", errors.New("this agentgate is a temporary `go run` build; install it (brew, go install or a release binary) and run init from the installed one")
	}
	return path, nil
}
