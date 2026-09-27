package telemetry

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type collector struct {
	mu      sync.Mutex
	bodies  []map[string]any
	headers []http.Header
	paths   []string
}

func newCollector(t *testing.T) (*collector, *httptest.Server) {
	c := &collector{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		require.NoError(t, json.Unmarshal(raw, &body))
		c.mu.Lock()
		c.bodies = append(c.bodies, body)
		c.headers = append(c.headers, r.Header.Clone())
		c.paths = append(c.paths, r.URL.Path)
		c.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return c, srv
}

func (c *collector) spans() []map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []map[string]any
	for _, b := range c.bodies {
		for _, rs := range b["resourceSpans"].([]any) {
			for _, ss := range rs.(map[string]any)["scopeSpans"].([]any) {
				for _, s := range ss.(map[string]any)["spans"].([]any) {
					out = append(out, s.(map[string]any))
				}
			}
		}
	}
	return out
}

func attrs(span map[string]any) map[string]any {
	out := map[string]any{}
	for _, a := range span["attributes"].([]any) {
		kv := a.(map[string]any)
		for _, v := range kv["value"].(map[string]any) {
			out[kv["key"].(string)] = v
		}
	}
	return out
}

func TestExport(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", "x-team=a%20b,x-other=1")
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "deployment.environment=test")
	c, srv := newCollector(t)
	e, err := New(Config{Endpoint: srv.URL, Headers: map[string]string{"x-other": "2"}}, "v9", nil)
	require.NoError(t, err)

	start := time.Unix(1_800_000_000, 0)
	e.Export(Span{CallID: "c1", SessionID: "s1", Tool: "fs__write_file", Upstream: "fs", HostName: "code", Start: start,
		Duration: 150 * time.Millisecond, Decision: "deny", RuleID: "baseline/rm-rf-root", Reason: "no", Labels: []string{"private-data"}})
	e.Export(Span{CallID: "c2", SessionID: "s1", Tool: "fs__read_file", Upstream: "fs", Start: start, Decision: "allow"})
	e.Export(Span{CallID: "c3", SessionID: "s2", Tool: "fs__read_file", Upstream: "fs", Start: start, Decision: "deny", Shadow: true})
	require.NoError(t, e.Close(context.Background()))

	spans := c.spans()
	require.Len(t, spans, 3)
	denied, allowed, shadow := spans[0], spans[1], spans[2]
	require.Equal(t, "tools/call fs__write_file", denied["name"])
	require.Equal(t, denied["traceId"], allowed["traceId"], "one trace per session")
	require.NotEqual(t, denied["traceId"], shadow["traceId"])
	require.Len(t, denied["traceId"], 32)
	require.Len(t, denied["spanId"], 16)
	require.Equal(t, "1800000000000000000", denied["startTimeUnixNano"])
	require.Equal(t, "1800000000150000000", denied["endTimeUnixNano"])
	require.EqualValues(t, 2, denied["status"].(map[string]any)["code"])
	require.EqualValues(t, 0, allowed["status"].(map[string]any)["code"])
	require.EqualValues(t, 0, shadow["status"].(map[string]any)["code"], "a shadow deny did not stop anything")

	a := attrs(denied)
	require.Equal(t, "fs__write_file", a["gen_ai.tool.name"])
	require.Equal(t, "tools/call", a["mcp.method.name"])
	require.Equal(t, "execute_tool", a["gen_ai.operation.name"])
	require.Equal(t, "baseline/rm-rf-root", a["agentgate.rule_id"])
	require.Equal(t, "150", a["agentgate.duration_ms"], "OTLP JSON carries integers as strings")

	c.mu.Lock()
	defer c.mu.Unlock()
	require.Equal(t, "/v1/traces", c.paths[0])
	require.Equal(t, "a b", c.headers[0].Get("x-team"))
	require.Equal(t, "2", c.headers[0].Get("x-other"), "the config file wins over the environment")
	res := c.bodies[0]["resourceSpans"].([]any)[0].(map[string]any)["resource"].(map[string]any)
	resAttrs := attrs(res)
	require.Equal(t, "agentgate", resAttrs["service.name"])
	require.Equal(t, "v9", resAttrs["service.version"])
	require.Equal(t, "test", resAttrs["deployment.environment"])
}

func TestDisabledWithoutEndpoint(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "")
	e, err := New(Config{}, "v", nil)
	require.NoError(t, err)
	require.Nil(t, e)
	e.Export(Span{})
	require.NoError(t, e.Close(context.Background()))

	_, err = New(Config{Endpoint: "ftp://x"}, "v", nil)
	require.Error(t, err)
}

func TestTracesEndpointIsUsedAsIs(t *testing.T) {
	c, srv := newCollector(t)
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", srv.URL+"/custom/path")
	e, err := New(Config{}, "v", nil)
	require.NoError(t, err)
	e.Export(Span{SessionID: "s", Tool: "x", Start: time.Now(), Decision: "allow"})
	require.NoError(t, e.Close(context.Background()))
	c.mu.Lock()
	defer c.mu.Unlock()
	require.Equal(t, []string{"/custom/path"}, c.paths)
}
