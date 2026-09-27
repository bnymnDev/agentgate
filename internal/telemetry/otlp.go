// Package telemetry exports every tool call as an OpenTelemetry span, over
// OTLP/HTTP with JSON encoding, so agentgate's decisions show up next to the
// rest of your traces in Jaeger, Tempo, Honeycomb, Datadog or anything else
// that speaks OTLP.
//
// Each session is one trace and each call a span in it, named the way the
// MCP semantic conventions name them ("tools/call write_file") and carrying
// the GenAI and MCP attributes plus agentgate's own: the decision, the rule
// and the reason.
package telemetry

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Config is where spans go. The OTEL_* environment variables fill in what
// the config file leaves out, so an existing OpenTelemetry setup works as is.
type Config struct {
	// Endpoint is the OTLP/HTTP base URL, e.g. http://localhost:4318. Spans
	// are posted to <endpoint>/v1/traces.
	Endpoint string `yaml:"endpoint"`
	// Headers are sent with every export, e.g. an API key.
	Headers map[string]string `yaml:"headers"`
	// ServiceName defaults to agentgate.
	ServiceName string `yaml:"service_name"`
}

// Span is one tool call as it is exported.
type Span struct {
	CallID      string
	SessionID   string
	Tool        string
	Upstream    string
	HostName    string
	HostVersion string
	Start       time.Time
	Duration    time.Duration
	Decision    string
	RuleID      string
	Reason      string
	IsError     bool
	Error       string
	Shadow      bool
	Labels      []string
}

// Exporter batches spans and posts them in the background. A slow or dead
// collector never slows a tool call down: when the buffer is full, spans are
// dropped and counted.
type Exporter struct {
	url      string
	headers  map[string]string
	resource []attr
	client   *http.Client
	log      *slog.Logger

	spans   chan Span
	done    chan struct{}
	wg      sync.WaitGroup
	once    sync.Once
	mu      sync.Mutex
	dropped int
}

// New returns an exporter, or nil when no endpoint is configured anywhere.
func New(cfg Config, version string, log *slog.Logger) (*Exporter, error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	target := os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
	if target == "" {
		base := cfg.Endpoint
		if base == "" {
			base = os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
		}
		if base == "" {
			return nil, nil
		}
		target = strings.TrimRight(base, "/") + "/v1/traces"
	}
	u, err := url.Parse(target)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("telemetry: %q is not an http(s) OTLP endpoint", target)
	}
	switch p := os.Getenv("OTEL_EXPORTER_OTLP_PROTOCOL"); p {
	case "", "http/json":
	default:
		log.Warn("telemetry: agentgate exports OTLP over HTTP with JSON encoding; the collector must accept http/json", "OTEL_EXPORTER_OTLP_PROTOCOL", p)
	}
	headers := parseKV(os.Getenv("OTEL_EXPORTER_OTLP_HEADERS"))
	for k, v := range parseKV(os.Getenv("OTEL_EXPORTER_OTLP_TRACES_HEADERS")) {
		headers[k] = v
	}
	for k, v := range cfg.Headers {
		headers[k] = v
	}
	service := cfg.ServiceName
	if s := os.Getenv("OTEL_SERVICE_NAME"); service == "" && s != "" {
		service = s
	}
	if service == "" {
		service = "agentgate"
	}
	resource := []attr{str("service.name", service), str("service.version", version), str("telemetry.sdk.name", "agentgate")}
	for k, v := range parseKV(os.Getenv("OTEL_RESOURCE_ATTRIBUTES")) {
		if k != "service.name" {
			resource = append(resource, str(k, v))
		}
	}
	e := &Exporter{
		url:      target,
		headers:  headers,
		resource: resource,
		client:   &http.Client{Timeout: 10 * time.Second},
		log:      log,
		spans:    make(chan Span, 2048),
		done:     make(chan struct{}),
	}
	e.wg.Add(1)
	go e.run()
	log.Info("exporting tool calls as OpenTelemetry spans", "endpoint", target)
	return e, nil
}

// Export queues a span. It never blocks.
func (e *Exporter) Export(s Span) {
	if e == nil {
		return
	}
	select {
	case <-e.done:
		return
	default:
	}
	select {
	case e.spans <- s:
	default:
		e.mu.Lock()
		e.dropped++
		n := e.dropped
		e.mu.Unlock()
		if n == 1 || n%1000 == 0 {
			e.log.Warn("telemetry: span buffer full, spans dropped", "dropped_total", n)
		}
	}
}

// Close flushes what is queued, waiting at most until ctx is done.
func (e *Exporter) Close(ctx context.Context) error {
	if e == nil {
		return nil
	}
	e.once.Do(func() { close(e.done) })
	finished := make(chan struct{})
	go func() {
		e.wg.Wait()
		close(finished)
	}()
	select {
	case <-finished:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (e *Exporter) run() {
	defer e.wg.Done()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	var batch []Span
	flush := func() {
		if len(batch) == 0 {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := e.post(ctx, batch); err != nil {
			e.log.Warn("telemetry: export failed, spans dropped", "spans", len(batch), "error", err)
		}
		cancel()
		batch = batch[:0]
	}
	for {
		select {
		case s := <-e.spans:
			batch = append(batch, s)
			if len(batch) >= 256 {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-e.done:
			for {
				select {
				case s := <-e.spans:
					batch = append(batch, s)
				default:
					flush()
					return
				}
			}
		}
	}
}

func (e *Exporter) post(ctx context.Context, spans []Span) error {
	body, err := json.Marshal(e.payload(spans))
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range e.headers {
		req.Header.Set(k, v)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("collector answered %s", resp.Status)
	}
	return nil
}

// The OTLP/JSON shapes. Ids are hex, times are nanoseconds as strings, and
// integers are strings too, as the OTLP JSON encoding requires.
type (
	attr struct {
		Key   string `json:"key"`
		Value value  `json:"value"`
	}
	value struct {
		String *string     `json:"stringValue,omitempty"`
		Bool   *bool       `json:"boolValue,omitempty"`
		Int    *string     `json:"intValue,omitempty"`
		Array  *arrayValue `json:"arrayValue,omitempty"`
	}
	arrayValue struct {
		Values []value `json:"values"`
	}
	otlpSpan struct {
		TraceID    string     `json:"traceId"`
		SpanID     string     `json:"spanId"`
		Name       string     `json:"name"`
		Kind       int        `json:"kind"`
		Start      string     `json:"startTimeUnixNano"`
		End        string     `json:"endTimeUnixNano"`
		Attributes []attr     `json:"attributes"`
		Status     otlpStatus `json:"status"`
	}
	otlpStatus struct {
		Code    int    `json:"code"`
		Message string `json:"message,omitempty"`
	}
)

func str(k, v string) attr { return attr{Key: k, Value: value{String: &v}} }
func boolean(k string, v bool) attr {
	return attr{Key: k, Value: value{Bool: &v}}
}
func integer(k string, v int64) attr {
	s := strconv.FormatInt(v, 10)
	return attr{Key: k, Value: value{Int: &s}}
}
func stringList(k string, vs []string) attr {
	arr := &arrayValue{}
	for _, v := range vs {
		arr.Values = append(arr.Values, value{String: &v})
	}
	return attr{Key: k, Value: value{Array: arr}}
}

const (
	kindServer  = 2
	statusUnset = 0
	statusError = 2
)

func (e *Exporter) payload(spans []Span) map[string]any {
	out := make([]otlpSpan, 0, len(spans))
	for _, s := range spans {
		out = append(out, toOTLP(s))
	}
	return map[string]any{
		"resourceSpans": []any{map[string]any{
			"resource": map[string]any{"attributes": e.resource},
			"scopeSpans": []any{map[string]any{
				"scope": map[string]any{"name": "github.com/bnymnDev/agentgate"},
				"spans": out,
			}},
		}},
	}
}

func toOTLP(s Span) otlpSpan {
	attrs := []attr{
		str("mcp.method.name", "tools/call"),
		str("gen_ai.operation.name", "execute_tool"),
		str("gen_ai.tool.name", s.Tool),
		str("mcp.session.id", s.SessionID),
		str("agentgate.upstream", s.Upstream),
		str("agentgate.decision", s.Decision),
	}
	if s.CallID != "" {
		attrs = append(attrs, str("gen_ai.tool.call.id", s.CallID))
	}
	if s.HostName != "" {
		attrs = append(attrs, str("agentgate.host.name", s.HostName))
	}
	if s.HostVersion != "" {
		attrs = append(attrs, str("agentgate.host.version", s.HostVersion))
	}
	if s.RuleID != "" {
		attrs = append(attrs, str("agentgate.rule_id", s.RuleID))
	}
	if s.Reason != "" {
		attrs = append(attrs, str("agentgate.reason", s.Reason))
	}
	if s.Shadow {
		attrs = append(attrs, boolean("agentgate.shadow", true))
	}
	if len(s.Labels) > 0 {
		attrs = append(attrs, stringList("agentgate.labels", s.Labels))
	}
	attrs = append(attrs, integer("agentgate.duration_ms", s.Duration.Milliseconds()))

	status := otlpStatus{Code: statusUnset}
	switch {
	case s.Decision != "allow" && !s.Shadow:
		status = otlpStatus{Code: statusError, Message: "denied: " + s.Reason}
		attrs = append(attrs, str("error.type", "agentgate.denied"))
	case s.Error != "":
		status = otlpStatus{Code: statusError, Message: s.Error}
		attrs = append(attrs, str("error.type", "agentgate.upstream_error"))
	case s.IsError:
		status = otlpStatus{Code: statusError, Message: "the tool reported an error"}
		attrs = append(attrs, str("error.type", "tool_error"))
	}
	end := s.Start.Add(s.Duration)
	return otlpSpan{
		TraceID:    traceID(s.SessionID),
		SpanID:     spanID(s.CallID),
		Name:       "tools/call " + s.Tool,
		Kind:       kindServer,
		Start:      strconv.FormatInt(s.Start.UnixNano(), 10),
		End:        strconv.FormatInt(end.UnixNano(), 10),
		Attributes: attrs,
		Status:     status,
	}
}

// traceID derives a session's trace id from its id, so every call of a
// session lands in one trace without any state to keep.
func traceID(session string) string {
	sum := sha256.Sum256([]byte("agentgate-session:" + session))
	return hex.EncodeToString(sum[:16])
}

func spanID(call string) string {
	if call == "" {
		b := make([]byte, 8)
		_, _ = rand.Read(b)
		return hex.EncodeToString(b)
	}
	sum := sha256.Sum256([]byte("agentgate-call:" + call))
	return hex.EncodeToString(sum[:8])
}

// parseKV reads the k=v,k2=v2 lists the OTEL_* variables use; values may be
// percent-encoded.
func parseKV(s string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		if dec, err := url.QueryUnescape(strings.TrimSpace(v)); err == nil {
			v = dec
		}
		if k != "" {
			out[k] = v
		}
	}
	return out
}
