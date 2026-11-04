package cli

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/spf13/cobra"

	"github.com/bnymnDev/agentgate/internal/config"
	"github.com/bnymnDev/agentgate/internal/passkey"
)

func newPasskeyCmd(g *globals) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "passkey",
		Short: "Enrol the passkeys that sign approvals in the web UI",
		Long: `With approval.passkeys in the config, an approval in the web UI is signed by
a passkey — a phone, a security key, a fingerprint reader — over the exact
question it answers, and the audit log keeps the signature. With required:
true, nothing else can approve.

	agentgate passkey enroll     print a one-time code, then enrol on the Passkeys page
	agentgate passkey list
	agentgate passkey rm "work laptop"

Open the web UI at http://localhost:<port>: browsers do not offer passkeys
on a bare IP address.`,
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "enroll",
		Short: "Print a one-time code that allows enrolling one passkey",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, err := passkeyStore(g)
			if err != nil {
				return err
			}
			code, err := store.NewEnrollCode(10 * time.Minute)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s\n\nEnter it on the Passkeys page of the web UI within ten minutes. It allows one passkey.\n", code)
			return nil
		},
	}, &cobra.Command{
		Use:   "list",
		Short: "List the enrolled passkeys",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, err := passkeyStore(g)
			if err != nil {
				return err
			}
			list, err := store.List()
			if err != nil {
				return err
			}
			t := newTable(cmd.OutOrStdout(), "NAME", "ENROLLED", "LAST USED")
			for _, r := range list {
				last := "never"
				if !r.LastUsed.IsZero() {
					last = r.LastUsed.Local().Format(time.DateTime)
				}
				t.row(r.Name, r.CreatedAt.Local().Format(time.DateTime), last)
			}
			t.flush()
			return nil
		},
	}, &cobra.Command{
		Use:   "rm <name>",
		Short: "Remove a passkey",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := passkeyStore(g)
			if err != nil {
				return err
			}
			if err := store.Remove(args[0]); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "removed %s\n", args[0])
			return nil
		},
	})
	return cmd
}

func passkeyStore(g *globals) (*passkey.Store, error) {
	cfg, err := g.load()
	if err != nil {
		return nil, err
	}
	if cfg.Approval.Passkeys == nil {
		return nil, errors.New("passkeys are off; add approval.passkeys to the config")
	}
	return passkey.Open(cfg.Approval.Passkeys.Store), nil
}

// passkeyService is the passkey service for a web UI listening on addr.
func passkeyService(cfg *config.Config, addr string) (*passkey.Service, error) {
	pk := cfg.Approval.Passkeys
	if pk == nil {
		return nil, nil
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("--ui %q: %w", addr, err)
	}
	origins := []string{"http://" + pk.RPID + ":" + port, "https://" + pk.RPID + ":" + port}
	return passkey.NewService(passkey.Open(pk.Store), pk.RPID, origins)
}
