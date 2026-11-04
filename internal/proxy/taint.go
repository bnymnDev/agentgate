package proxy

import "github.com/bnymnDev/agentgate/internal/policy"

// taintHit reports a value the session read from a private result on its way
// out. See taint tracking.
func (p *Proxy) taintHit(st *sessionState, text string) (policy.Decision, bool) {
	return policy.Decision{}, false
}

func (p *Proxy) taintsFrom(st *sessionState, what string, labels []string) bool { return false }

func (p *Proxy) taint(st *sessionState, text string) {}
