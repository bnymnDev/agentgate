// Package mock turns a recorded session into an MCP server that answers
// with what the real servers answered at the time. Point an agent, a test or
// a new policy at it and it sees the same tools and gets the same results,
// with nothing real behind them: no filesystem, no network, no side effects.
package mock

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/bnymnDev/agentgate/internal/audit"
	"github.com/bnymnDev/agentgate/internal/policy"
)

// Options shape the mock.
type Options struct {
	// Strict answers a call nothing was recorded for — same tool, same
	// arguments — with an error. Without it, such a call gets the next
	// recorded result of the same tool.
	Strict bool
	// Version is advertised as the server's version.
	Version string
}

// Server is a recorded session, served.
type Server struct {
	opts Options

	mu sync.Mutex
	// exact holds the recorded results per tool and argument hash, in the
	// order they were recorded; byTool holds them per tool.
	exact  map[string]*queue
	byTool map[string]*queue
	tools  []*mcp.Tool
}

type queue struct {
	results []json.RawMessage
	next    int
}

// pop returns the next result; the last one repeats once they run out.
func (q *queue) pop() json.RawMessage {
	r := q.results[q.next]
	if q.next < len(q.results)-1 {
		q.next++
	}
	return r
}

// New builds a mock from a session's calls and its catalog snapshot. A nil
// catalog — a session recorded before snapshots existed — means the tools
// are made up from the calls, with a schema that accepts anything.
func New(calls []*audit.Call, catalog []byte, opts Options) (*Server, error) {
	s := &Server{opts: opts, exact: map[string]*queue{}, byTool: map[string]*queue{}}
	for _, c := range calls {
		// Only calls the upstream answered have a result worth replaying:
		// a denied call's result is agentgate's, not the server's.
		if c.Decision != policy.ActionAllow && !c.Shadow {
			continue
		}
		if len(c.Result) == 0 || c.ResultTruncated || !json.Valid(c.Result) {
			continue
		}
		key := c.Tool + "\x00" + audit.Hash(c.Args)
		if s.exact[key] == nil {
			s.exact[key] = &queue{}
		}
		s.exact[key].results = append(s.exact[key].results, c.Result)
		if s.byTool[c.Tool] == nil {
			s.byTool[c.Tool] = &queue{}
		}
		s.byTool[c.Tool].results = append(s.byTool[c.Tool].results, c.Result)
	}

	seen := map[string]bool{}
	if len(catalog) > 0 {
		var entries []audit.CatalogEntry
		if err := json.Unmarshal(catalog, &entries); err != nil {
			return nil, fmt.Errorf("reading the recorded catalog: %w", err)
		}
		for _, e := range entries {
			var t mcp.Tool
			if err := json.Unmarshal(e.Tool, &t); err != nil {
				continue
			}
			t.Name = e.Exposed
			if t.InputSchema == nil {
				t.InputSchema = map[string]any{"type": "object"}
			}
			s.tools = append(s.tools, &t)
			seen[t.Name] = true
		}
	}
	var extra []string
	for _, c := range calls {
		if !seen[c.Tool] {
			seen[c.Tool] = true
			extra = append(extra, c.Tool)
		}
	}
	sort.Strings(extra)
	for _, name := range extra {
		s.tools = append(s.tools, &mcp.Tool{
			Name:        name,
			Description: "Recorded by agentgate; the definition was not captured.",
			InputSchema: map[string]any{"type": "object"},
		})
	}
	return s, nil
}

// Tools lists what the mock serves.
func (s *Server) Tools() []*mcp.Tool { return s.tools }

// MCP returns the server to connect a transport to.
func (s *Server) MCP() *mcp.Server {
	version := s.opts.Version
	if version == "" {
		version = "dev"
	}
	srv := mcp.NewServer(&mcp.Implementation{Name: "agentgate-mock", Version: version},
		&mcp.ServerOptions{Instructions: "A recorded session, replayed by agentgate mock. Nothing here has any effect."})
	for _, t := range s.tools {
		srv.AddTool(t, s.handler(t.Name))
	}
	return srv
}

func (s *Server) handler(tool string) mcp.ToolHandler {
	return func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		raw, found := s.answer(tool, req.Params.Arguments)
		if !found {
			msg := fmt.Sprintf("agentgate mock: %s was never answered in the recorded session", tool)
			if s.opts.Strict {
				msg = fmt.Sprintf("agentgate mock: no recording of %s with these arguments (--strict)", tool)
			}
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: msg}}}, nil
		}
		var res mcp.CallToolResult
		if err := json.Unmarshal(raw, &res); err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{
				Text: "agentgate mock: the recorded result cannot be read: " + err.Error()}}}, nil
		}
		return &res, nil
	}
}

// answer finds the recorded result for a call: the same tool with the same
// arguments first, then — unless strict — the tool's next recorded result.
func (s *Server) answer(tool string, args json.RawMessage) (json.RawMessage, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if q := s.exact[tool+"\x00"+audit.Hash(args)]; q != nil {
		return q.pop(), true
	}
	if s.opts.Strict {
		return nil, false
	}
	if q := s.byTool[tool]; q != nil {
		return q.pop(), true
	}
	return nil, false
}
