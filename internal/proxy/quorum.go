package proxy

import (
	"context"
	"fmt"
	"strings"

	"github.com/bnymnDev/agentgate/internal/policy"
)

// quorum asks every channel and waits for req.Quorum approvals by
// different people. A chat counts each person in it once, so two people in
// one Slack channel are a quorum of two; a channel that does not know who
// answered — the terminal, the web UI, the phone — counts as one person.
// Anyone denying denies at once.
func (f FanoutApprover) quorum(ctx context.Context, req ApprovalRequest) (Verdict, error) {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	out := make(chan Verdict, 64)
	finished := make(chan error, len(f))
	running := 0
	for _, a := range f {
		if a == nil {
			continue
		}
		running++
		go func(a Approver) {
			if c, ok := a.(Collector); ok {
				finished <- c.Collect(ctx, req, out)
				return
			}
			v, err := a.Approve(ctx, req)
			if err == nil {
				out <- v
			}
			finished <- err
		}(a)
	}
	var (
		approved []Verdict
		seen     = map[string]bool{}
		lastErr  error
	)
	short := func(why string) Verdict {
		return Verdict{Decision: policy.Decision{Action: policy.ActionDeny,
			Reason: fmt.Sprintf("%s with %d of %d approvals", why, len(approved), req.Quorum)}}
	}
	for {
		select {
		case v := <-out:
			if v.Channel == "" {
				continue // a channel giving up, not a person answering
			}
			if v.Action != policy.ActionAllow {
				cancel(settled{v})
				return v, nil
			}
			key := v.Channel + "\x00" + v.Who
			if v.Who != "" {
				key = v.Who
			}
			if seen[key] {
				continue
			}
			seen[key] = true
			approved = append(approved, v)
			if len(approved) >= req.Quorum {
				v := combine(approved)
				cancel(settled{v})
				return v, nil
			}
		case err := <-finished:
			running--
			if err != nil {
				lastErr = err
			}
			if running == 0 {
				if len(approved) == 0 && lastErr != nil {
					return Verdict{}, lastErr
				}
				v := short("approval incomplete: every channel closed")
				cancel(settled{v})
				return v, nil
			}
		case <-ctx.Done():
			return short("approval timed out"), nil
		}
	}
}

// combine joins the approvals of a quorum into one verdict. It is for the
// session only if every one of them said so.
func combine(vs []Verdict) Verdict {
	reasons := make([]string, len(vs))
	session := true
	for i, v := range vs {
		reasons[i] = v.Reason
		session = session && v.Session
	}
	return Verdict{
		Decision: policy.Decision{Action: policy.ActionAllow,
			Reason: fmt.Sprintf("approved by %d people: %s", len(vs), strings.Join(reasons, "; "))},
		Session: session,
	}
}
