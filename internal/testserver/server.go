// Package testserver is a small but real MCP server. It backs `make dev`, the
// end-to-end test and the proxy unit tests, so that agentgate is always
// exercised against an actual MCP implementation rather than a mock of one.
package testserver

import (
	"context"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Name is the implementation name the demo server reports.
const Name = "agentgate-echo"

type echoArgs struct {
	Text string `json:"text" jsonschema:"the text to echo back"`
}

type addArgs struct {
	A float64 `json:"a" jsonschema:"the first number"`
	B float64 `json:"b" jsonschema:"the second number"`
}

type addResult struct {
	Sum float64 `json:"sum" jsonschema:"the sum of a and b"`
}

type writeArgs struct {
	Path     string `json:"path" jsonschema:"where to write"`
	Contents string `json:"contents,omitempty" jsonschema:"what to write"`
}

type execArgs struct {
	Command string `json:"command" jsonschema:"the shell command to run"`
}

type queryArgs struct {
	SQL string `json:"sql" jsonschema:"the SQL to run"`
}

type slowArgs struct {
	MS int `json:"ms" jsonschema:"how long to take, in milliseconds"`
}

type failArgs struct {
	Message string `json:"message,omitempty" jsonschema:"the error text to return"`
}

// New returns a demo MCP server with one tool per behaviour agentgate needs to
// be able to handle: a plain result, a structured result, a slow call, a tool
// error, and a result that contains something a redaction rule should catch.
//
// Nothing here touches the filesystem or runs a command; write_file and exec
// only describe what they would have done.
func New() *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: Name, Version: "1.0.0"}, &mcp.ServerOptions{
		Instructions: "A demo server for trying agentgate out. Nothing it does has any effect.",
	})

	mcp.AddTool(s, &mcp.Tool{Name: "echo", Description: "Echo the text back"},
		func(_ context.Context, _ *mcp.CallToolRequest, in echoArgs) (*mcp.CallToolResult, any, error) {
			return text(in.Text), nil, nil
		})

	mcp.AddTool(s, &mcp.Tool{Name: "add", Description: "Add two numbers"},
		func(_ context.Context, _ *mcp.CallToolRequest, in addArgs) (*mcp.CallToolResult, addResult, error) {
			return nil, addResult{Sum: in.A + in.B}, nil
		})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "write_file",
		Description: "Pretend to write a file",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: boolPtr(true), IdempotentHint: true},
	},
		func(_ context.Context, _ *mcp.CallToolRequest, in writeArgs) (*mcp.CallToolResult, any, error) {
			return text(fmt.Sprintf("would write %d bytes to %s", len(in.Contents), in.Path)), nil, nil
		})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "read_file",
		Description: "Pretend to read a file",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, DestructiveHint: boolPtr(false)},
	},
		func(_ context.Context, _ *mcp.CallToolRequest, in writeArgs) (*mcp.CallToolResult, any, error) {
			return text("contents of " + in.Path), nil, nil
		})

	mcp.AddTool(s, &mcp.Tool{Name: "exec", Description: "Pretend to run a shell command"},
		func(_ context.Context, _ *mcp.CallToolRequest, in execArgs) (*mcp.CallToolResult, any, error) {
			return text("would run: " + in.Command), nil, nil
		})

	mcp.AddTool(s, &mcp.Tool{Name: "query", Description: "Pretend to run a SQL query"},
		func(_ context.Context, _ *mcp.CallToolRequest, in queryArgs) (*mcp.CallToolResult, any, error) {
			return text("would run: " + in.SQL), nil, nil
		})

	mcp.AddTool(s, &mcp.Tool{Name: "slow", Description: "Take a while to answer"},
		func(ctx context.Context, _ *mcp.CallToolRequest, in slowArgs) (*mcp.CallToolResult, any, error) {
			select {
			case <-time.After(time.Duration(in.MS) * time.Millisecond):
				return text(fmt.Sprintf("slept %dms", in.MS)), nil, nil
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			}
		})

	mcp.AddTool(s, &mcp.Tool{Name: "fail", Description: "Return a tool error"},
		func(_ context.Context, _ *mcp.CallToolRequest, in failArgs) (*mcp.CallToolResult, any, error) {
			msg := in.Message
			if msg == "" {
				msg = "this tool always fails"
			}
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: msg}}}, nil, nil
		})

	mcp.AddTool(s, &mcp.Tool{Name: "leak", Description: "Return something a redaction rule should catch"},
		func(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
			return text("api_key=sk-not-a-real-key-0123456789abcdef and we are done"), nil, nil
		})

	s.AddResource(&mcp.Resource{
		URI:         "demo://readme",
		Name:        "readme",
		Description: "A resource, to prove that resources pass through untouched",
		MIMEType:    "text/plain",
	}, func(_ context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{
			URI: req.Params.URI, MIMEType: "text/plain", Text: "agentgate demo resource",
		}}}, nil
	})

	s.AddPrompt(&mcp.Prompt{
		Name:        "greet",
		Description: "A prompt, to prove that prompts pass through untouched",
	}, func(_ context.Context, _ *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		return &mcp.GetPromptResult{
			Description: "a greeting",
			Messages: []*mcp.PromptMessage{{
				Role: "user", Content: &mcp.TextContent{Text: "Say hello."},
			}},
		}, nil
	})

	return s
}

func boolPtr(b bool) *bool { return &b }

func text(s string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: s}}}
}
