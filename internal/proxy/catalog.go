package proxy

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/bnymnDev/agentgate/internal/policy"
)

// catalog is the merged view of everything the upstreams offer. It exists so
// that a refresh can compute the difference and remove features that went away,
// which is what turns an upstream's list_changed notification into a correct
// list_changed for the host.
type catalog struct {
	transport string

	mu        sync.Mutex
	tools     map[string]*ToolBinding
	resources map[string]string // uri -> upstream name
	templates map[string]string // uriTemplate -> upstream name
	prompts   map[string]string // prompt name -> upstream name
	honeypots map[string]bool   // decoys currently registered on the server
}

// ToolBinding maps an exposed tool name back to its upstream.
type ToolBinding struct {
	// Exposed is the name the host sees, prefix included.
	Exposed string
	// Name is the name the upstream server uses.
	Name string
	// Upstream is the configured upstream name.
	Upstream string
	// Annotations are the server's hints about the tool, for annotations.*
	// conditions.
	Annotations policy.Annotations
}

// annotationsOf translates the server's hints into the policy's view of them,
// applying the MCP defaults: a tool that has annotations but says nothing
// about destructiveHint is destructive, and one that says nothing about
// openWorldHint is open-world. A tool with no annotations at all says nothing,
// and every annotations.* condition on it is missing.
func annotationsOf(t *mcp.Tool) policy.Annotations {
	if t.Annotations == nil {
		return policy.Annotations{}
	}
	a := t.Annotations
	readOnly, idempotent := a.ReadOnlyHint, a.IdempotentHint
	destructive, openWorld := true, true
	if a.DestructiveHint != nil {
		destructive = *a.DestructiveHint
	}
	if a.OpenWorldHint != nil {
		openWorld = *a.OpenWorldHint
	}
	return policy.Annotations{
		Title:       a.Title,
		ReadOnly:    &readOnly,
		Destructive: &destructive,
		Idempotent:  &idempotent,
		OpenWorld:   &openWorld,
	}
}

// Tools returns the current catalog, sorted by exposed name.
func (p *Proxy) Tools() []ToolBinding {
	p.catalog.mu.Lock()
	defer p.catalog.mu.Unlock()
	out := make([]ToolBinding, 0, len(p.catalog.tools))
	for _, b := range p.catalog.tools {
		out = append(out, *b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Exposed < out[j].Exposed })
	return out
}

// Lookup resolves an exposed tool name to its binding.
func (p *Proxy) Lookup(exposed string) (ToolBinding, bool) {
	p.catalog.mu.Lock()
	defer p.catalog.mu.Unlock()
	b, ok := p.catalog.tools[exposed]
	if !ok {
		return ToolBinding{}, false
	}
	return *b, true
}

// Refresh rebuilds the merged catalog from every reachable upstream and
// registers it on the downstream server. Adding and removing features on the
// server is what makes the SDK emit the matching list_changed notifications.
func (p *Proxy) Refresh(ctx context.Context) error {
	// Two upstreams announcing changes at once must not interleave their
	// add/remove calls on the server.
	p.refreshMu.Lock()
	defer p.refreshMu.Unlock()

	cfg := p.Config()
	var errs []error

	tools := map[string]*ToolBinding{}
	resources := map[string]string{}
	templates := map[string]string{}
	prompts := map[string]string{}

	type pending struct {
		tool     *mcp.Tool
		binding  *ToolBinding
		upstream *upstream
	}
	var newTools []pending
	var newResources []struct {
		res *mcp.Resource
		up  *upstream
	}
	var newTemplates []struct {
		tpl *mcp.ResourceTemplate
		up  *upstream
	}
	var newPrompts []struct {
		prompt *mcp.Prompt
		up     *upstream
	}

	for _, u := range p.upstreams {
		session, err := u.conn()
		if err != nil {
			errs = append(errs, err)
			continue
		}
		caps := u.capabilities()
		if caps == nil || caps.Tools != nil {
			for tool, err := range session.Tools(ctx, nil) {
				if err != nil {
					errs = append(errs, fmt.Errorf("listing tools of %q: %w", u.name(), err))
					break
				}
				exposed := cfg.Prefixed(u.cfg, tool.Name)
				if other, clash := tools[exposed]; clash {
					errs = append(errs, fmt.Errorf("tool name clash: %q is offered by both %q and %q; give one of them prefix: true",
						exposed, other.Upstream, u.name()))
					continue
				}
				binding := &ToolBinding{Exposed: exposed, Name: tool.Name, Upstream: u.name(), Annotations: annotationsOf(tool)}
				tools[exposed] = binding
				clone := *tool
				clone.Name = exposed
				newTools = append(newTools, pending{tool: &clone, binding: binding, upstream: u})
			}
		}
		if caps != nil && caps.Resources != nil {
			for res, err := range session.Resources(ctx, nil) {
				if err != nil {
					errs = append(errs, fmt.Errorf("listing resources of %q: %w", u.name(), err))
					break
				}
				if _, clash := resources[res.URI]; clash {
					continue // first upstream to claim a URI keeps it
				}
				resources[res.URI] = u.name()
				newResources = append(newResources, struct {
					res *mcp.Resource
					up  *upstream
				}{res, u})
			}
			for tpl, err := range session.ResourceTemplates(ctx, nil) {
				if err != nil {
					errs = append(errs, fmt.Errorf("listing resource templates of %q: %w", u.name(), err))
					break
				}
				if _, clash := templates[tpl.URITemplate]; clash {
					continue
				}
				templates[tpl.URITemplate] = u.name()
				newTemplates = append(newTemplates, struct {
					tpl *mcp.ResourceTemplate
					up  *upstream
				}{tpl, u})
			}
		}
		if caps != nil && caps.Prompts != nil {
			for prompt, err := range session.Prompts(ctx, nil) {
				if err != nil {
					errs = append(errs, fmt.Errorf("listing prompts of %q: %w", u.name(), err))
					break
				}
				if _, clash := prompts[prompt.Name]; clash {
					continue
				}
				prompts[prompt.Name] = u.name()
				newPrompts = append(newPrompts, struct {
					prompt *mcp.Prompt
					up     *upstream
				}{prompt, u})
			}
		}
	}

	p.catalog.mu.Lock()
	goneTools := missing(p.catalog.tools, tools)
	goneResources := missingSet(p.catalog.resources, resources)
	goneTemplates := missingSet(p.catalog.templates, templates)
	gonePrompts := missingSet(p.catalog.prompts, prompts)
	p.catalog.tools = tools
	p.catalog.resources = resources
	p.catalog.templates = templates
	p.catalog.prompts = prompts
	p.catalog.mu.Unlock()

	if len(goneTools) > 0 {
		p.server.RemoveTools(goneTools...)
	}
	if len(goneResources) > 0 {
		p.server.RemoveResources(goneResources...)
	}
	if len(goneTemplates) > 0 {
		p.server.RemoveResourceTemplates(goneTemplates...)
	}
	if len(gonePrompts) > 0 {
		p.server.RemovePrompts(gonePrompts...)
	}
	for _, t := range newTools {
		p.server.AddTool(t.tool, p.toolHandler(t.upstream, *t.binding))
	}
	for _, r := range newResources {
		p.server.AddResource(r.res, p.resourceHandler(r.up))
	}
	for _, t := range newTemplates {
		p.server.AddResourceTemplate(t.tpl, p.resourceHandler(t.up))
	}
	for _, pr := range newPrompts {
		p.server.AddPrompt(pr.prompt, p.promptHandler(pr.up))
	}
	p.registerHoneypots(cfg)

	p.log.Info("catalog refreshed",
		"tools", len(tools), "resources", len(resources), "prompts", len(prompts),
		"upstreams", len(p.upstreams))
	if len(errs) > 0 {
		return joinErrors(errs)
	}
	return nil
}

// upstreamFor returns the upstream that owns an exposed tool name.
func (p *Proxy) upstreamFor(name string) (*upstream, ToolBinding, bool) {
	b, ok := p.Lookup(name)
	if !ok {
		return nil, ToolBinding{}, false
	}
	u, ok := p.byName[b.Upstream]
	return u, b, ok
}

// ownerOfResource returns the upstream that listed a resource URI, if any.
func (p *Proxy) ownerOfResource(uri string) *upstream {
	p.catalog.mu.Lock()
	name, ok := p.catalog.resources[uri]
	p.catalog.mu.Unlock()
	if !ok {
		return nil
	}
	return p.byName[name]
}

// ownerOfPrompt returns the upstream that listed a prompt name, if any.
func (p *Proxy) ownerOfPrompt(name string) *upstream {
	p.catalog.mu.Lock()
	owner, ok := p.catalog.prompts[name]
	p.catalog.mu.Unlock()
	if !ok {
		return nil
	}
	return p.byName[owner]
}

func missing[T any](old map[string]T, current map[string]T) []string {
	var gone []string
	for k := range old {
		if _, ok := current[k]; !ok {
			gone = append(gone, k)
		}
	}
	sort.Strings(gone)
	return gone
}

func missingSet(old, current map[string]string) []string { return missing(old, current) }

func joinErrors(errs []error) error {
	msgs := make([]string, 0, len(errs))
	for _, err := range errs {
		msgs = append(msgs, err.Error())
	}
	return fmt.Errorf("%s", strings.Join(msgs, "; "))
}
