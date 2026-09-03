package observability

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// PayloadStage identifies one body-only point in the gateway data path. Header
// capture is deliberately absent: authentication and session headers are not
// eligible for trace export.
type PayloadStage string

const (
	PayloadStageClientRequest    PayloadStage = "client.request"
	PayloadStageProviderRequest  PayloadStage = "provider.request"
	PayloadStageProviderResponse PayloadStage = "provider.response"
	PayloadStageClientResponse   PayloadStage = "client.response"

	payloadEventName       = "gateway.payload"
	defaultPayloadMaxBytes = 16 << 20
	maxPayloadBytesCeiling = 16 << 20
	payloadRedactedValue   = "[REDACTED]"
)

// PayloadCaptureConfig is intentionally opt-in. Its zero value captures
// nothing, so callers must explicitly enable payload collection after their
// deployment's retention and access policy has been reviewed.
type PayloadCaptureConfig struct {
	Enabled  bool
	MaxBytes int
}

var configuredPayloadCapture atomic.Value

func init() {
	configuredPayloadCapture.Store(PayloadCaptureConfig{})
}

// ConfigurePayloadCapture installs the process-wide capture policy selected at
// startup. It is intentionally separate from the OpenTelemetry provider so
// callers can keep the request hot path free of provider plumbing.
func ConfigurePayloadCapture(cfg PayloadCaptureConfig) {
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = defaultPayloadMaxBytes
	}
	if cfg.MaxBytes > maxPayloadBytesCeiling {
		cfg.MaxBytes = maxPayloadBytesCeiling
	}
	configuredPayloadCapture.Store(cfg)
}

func configuredPayloadCapturePolicy() PayloadCaptureConfig {
	return configuredPayloadCapture.Load().(PayloadCaptureConfig)
}

// CaptureConfiguredPayload applies the startup policy to a sampled span.
func CaptureConfiguredPayload(span trace.Span, stage PayloadStage, body []byte) {
	CapturePayload(span, configuredPayloadCapturePolicy(), stage, body)
}

// CaptureRequestBody replays a request body through GetBody, so the forwarding
// request is never consumed or modified by observability.
func CaptureRequestBody(span trace.Span, req *http.Request) {
	if req == nil || req.GetBody == nil {
		return
	}
	cfg := configuredPayloadCapturePolicy()
	if !cfg.Enabled || span == nil || !span.IsRecording() || !span.SpanContext().IsSampled() {
		return
	}
	maxBytes := cfg.MaxBytes
	if maxBytes <= 0 {
		maxBytes = defaultPayloadMaxBytes
	}
	body, err := req.GetBody()
	if err != nil || body == nil {
		return
	}
	defer body.Close()
	data, err := io.ReadAll(io.LimitReader(body, int64(maxBytes)+1))
	if err != nil {
		return
	}
	capturePayload(span, cfg, PayloadStageProviderRequest, data, len(data) <= maxBytes)
}

// CapturePayload records a bounded, body-only payload event on an already
// sampled span. JSON is recursively redacted before it is limited. SSE is
// reduced to protocol framing plus redacted JSON data events; other formats
// export metadata only.
func CapturePayload(span trace.Span, cfg PayloadCaptureConfig, stage PayloadStage, body []byte) {
	capturePayload(span, cfg, stage, body, true)
}

func capturePayload(span trace.Span, cfg PayloadCaptureConfig, stage PayloadStage, body []byte, complete bool) {
	if !cfg.Enabled || !isPayloadStage(stage) || span == nil || !span.IsRecording() {
		return
	}
	spanContext := span.SpanContext()
	if !spanContext.IsValid() || !spanContext.IsSampled() {
		return
	}

	maxBytes := cfg.MaxBytes
	if maxBytes <= 0 {
		maxBytes = defaultPayloadMaxBytes
	}
	if maxBytes > maxPayloadBytesCeiling {
		maxBytes = maxPayloadBytesCeiling
	}

	digest := sha256.Sum256(body)
	attrs := []attribute.KeyValue{
		attribute.String("gateway.payload.stage", string(stage)),
		attribute.Int("gateway.payload.body_bytes", len(body)),
		attribute.String("gateway.payload.sha256", hex.EncodeToString(digest[:])),
		attribute.Bool("gateway.payload.complete", complete),
	}
	RecordInlineAttachmentManifests(span, stage, body)

	redactedJSON, redacted, validJSON := redactPayload(stage, body)
	if !validJSON {
		attrs = append(attrs,
			attribute.Int("gateway.payload.captured_bytes", 0),
			attribute.Bool("gateway.payload.truncated", len(body) > maxBytes),
			attribute.Bool("gateway.payload.redacted", false),
			attribute.Bool("gateway.payload.invalid_json", true),
		)
		span.AddEvent(payloadEventName, trace.WithAttributes(attrs...))
		return
	}

	captured := redactedJSON
	truncated := len(body) > maxBytes
	if len(captured) > maxBytes {
		captured = captured[:maxBytes]
		truncated = true
	}
	attrs = append(attrs,
		attribute.Int("gateway.payload.captured_bytes", len(captured)),
		attribute.Bool("gateway.payload.truncated", truncated),
		attribute.Bool("gateway.payload.redacted", redacted),
		attribute.Bool("gateway.payload.invalid_json", false),
		attribute.String("gateway.payload.body", safePayloadString(captured)),
	)
	span.AddEvent(payloadEventName, trace.WithAttributes(attrs...))
}

func redactPayload(stage PayloadStage, raw []byte) ([]byte, bool, bool) {
	if bytes.Contains(raw, []byte("data:")) || bytes.Contains(raw, []byte("event:")) {
		if sanitized, redacted, ok := redactPayloadSSE(stage, raw); ok {
			return sanitized, redacted, true
		}
	}
	return redactPayloadJSON(stage, raw)
}

// redactPayloadSSE keeps only protocol framing and JSON data events. A
// non-JSON data line is replaced instead of being exported as arbitrary text.
func redactPayloadSSE(stage PayloadStage, raw []byte) ([]byte, bool, bool) {
	frames := bytes.Split(raw, []byte("\n\n"))
	var out bytes.Buffer
	redacted := false
	validFrame := false
	for _, frame := range frames {
		frame = bytes.TrimSpace(frame)
		if len(frame) == 0 {
			continue
		}
		var frameOut bytes.Buffer
		for _, line := range bytes.Split(frame, []byte("\n")) {
			line = bytes.TrimSuffix(line, []byte("\r"))
			switch {
			case bytes.HasPrefix(line, []byte("event:")):
				frameOut.Write(line)
				frameOut.WriteByte('\n')
			case bytes.HasPrefix(line, []byte("data:")):
				value := bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
				if bytes.Equal(value, []byte("[DONE]")) {
					frameOut.WriteString("data: [DONE]\n")
				} else if sanitized, itemRedacted, ok := redactPayloadJSON(stage, value); ok {
					frameOut.WriteString("data: ")
					frameOut.Write(sanitized)
					frameOut.WriteByte('\n')
					redacted = redacted || itemRedacted
				} else {
					frameOut.WriteString("data: [REDACTED_NON_JSON]\n")
					redacted = true
				}
			default:
				continue
			}
		}
		if frameOut.Len() == 0 {
			continue
		}
		out.Write(frameOut.Bytes())
		out.WriteByte('\n')
		validFrame = true
	}
	if !validFrame {
		return nil, false, false
	}
	return out.Bytes(), redacted, true
}

func safePayloadString(value []byte) string {
	if utf8.Valid(value) {
		return string(value)
	}
	return strings.ToValidUTF8(string(value), "\uFFFD")
}

func isPayloadStage(stage PayloadStage) bool {
	switch stage {
	case PayloadStageClientRequest, PayloadStageProviderRequest, PayloadStageProviderResponse, PayloadStageClientResponse:
		return true
	default:
		return false
	}
}

func redactPayloadJSON(stage PayloadStage, raw []byte) ([]byte, bool, bool) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, false, false
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, false, false
	}

	redactedValue, redacted := redactPayloadValue(stage, value)
	encoded, err := json.Marshal(redactedValue)
	if err != nil {
		return nil, false, false
	}
	return encoded, redacted, true
}

func redactPayloadValue(stage PayloadStage, value any) (any, bool) {
	switch typed := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(typed))
		redacted := false
		for key, item := range typed {
			if isPayloadSensitiveKey(key) {
				result[key] = payloadRedactedValue
				redacted = true
				continue
			}
			if inlineValue, ok := item.(string); ok {
				if manifest, found := ExtractInlineAttachmentManifest(string(stage), key, inlineValue); found {
					result[key] = manifest.PayloadReference()
					redacted = true
					continue
				}
			}
			cleanItem, itemRedacted := redactPayloadValue(stage, item)
			result[key] = cleanItem
			redacted = redacted || itemRedacted
		}
		return result, redacted
	case []any:
		result := make([]any, len(typed))
		redacted := false
		for index, item := range typed {
			cleanItem, itemRedacted := redactPayloadValue(stage, item)
			result[index] = cleanItem
			redacted = redacted || itemRedacted
		}
		return result, redacted
	default:
		return value, false
	}
}

func isPayloadSensitiveKey(key string) bool {
	normalized := strings.NewReplacer("_", "", "-", "", " ", "").Replace(strings.ToLower(strings.TrimSpace(key)))
	if normalized == "" {
		return false
	}
	if normalized == "key" {
		return true
	}
	for _, marker := range []string{
		"authorization",
		"proxyauthorization",
		"cookie",
		"apikey",
		"bearer",
		"accesstoken",
		"refreshtoken",
		"oauth",
		"token",
		"password",
		"secret",
		"credential",
		"privatekey",
	} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

// WrapResponseBody tees a provider response into a bounded in-memory buffer.
// The original reader remains the source of truth for the forwarding path.
func WrapResponseBody(body io.ReadCloser, span trace.Span) io.ReadCloser {
	if body == nil {
		return body
	}
	cfg := configuredPayloadCapturePolicy()
	if !cfg.Enabled || span == nil || !span.IsRecording() || !span.SpanContext().IsSampled() {
		return body
	}
	maxBytes := cfg.MaxBytes
	if maxBytes <= 0 {
		maxBytes = defaultPayloadMaxBytes
	}
	if maxBytes > maxPayloadBytesCeiling {
		maxBytes = maxPayloadBytesCeiling
	}
	return &capturedBody{
		ReadCloser: body,
		span:       span,
		maxBytes:   maxBytes,
	}
}

type capturedBody struct {
	io.ReadCloser
	span       trace.Span
	maxBytes   int
	buffer     bytes.Buffer
	totalBytes int
	complete   bool
	once       sync.Once
}

func (b *capturedBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		b.totalBytes += n
		if b.buffer.Len() < b.maxBytes+1 {
			remaining := b.maxBytes + 1 - b.buffer.Len()
			if n < remaining {
				remaining = n
			}
			_, _ = b.buffer.Write(p[:remaining])
		}
	}
	if err == io.EOF {
		b.complete = true
		b.finalize()
	}
	return n, err
}

func (b *capturedBody) Close() error {
	err := b.ReadCloser.Close()
	b.finalize()
	return err
}

func (b *capturedBody) finalize() {
	b.once.Do(func() {
		capturePayload(b.span, configuredPayloadCapturePolicy(), PayloadStageProviderResponse, b.buffer.Bytes(), b.complete)
	})
}

// ResponseWriter captures bytes that were actually accepted by the client
// writer. It embeds Gin's writer so Flush/Hijack/CloseNotify/Pusher behavior is
// preserved for SSE and upgraded transports.
type ResponseWriter struct {
	gin.ResponseWriter
	span     trace.Span
	cfg      PayloadCaptureConfig
	buffer   bytes.Buffer
	maxBytes int
	once     sync.Once
}

func NewResponseWriter(writer gin.ResponseWriter, span trace.Span) *ResponseWriter {
	cfg := configuredPayloadCapturePolicy()
	maxBytes := cfg.MaxBytes
	if maxBytes <= 0 {
		maxBytes = defaultPayloadMaxBytes
	}
	if maxBytes > maxPayloadBytesCeiling {
		maxBytes = maxPayloadBytesCeiling
	}
	return &ResponseWriter{ResponseWriter: writer, span: span, cfg: cfg, maxBytes: maxBytes}
}

func (w *ResponseWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	w.captureWritten(p, n)
	return n, err
}

func (w *ResponseWriter) WriteString(value string) (int, error) {
	n, err := w.ResponseWriter.WriteString(value)
	if n > 0 {
		w.captureWritten([]byte(value), n)
	}
	return n, err
}

func (w *ResponseWriter) captureWritten(p []byte, n int) {
	if !w.cfg.Enabled || w.span == nil || !w.span.IsRecording() || !w.span.SpanContext().IsSampled() || n <= 0 {
		return
	}
	if n > len(p) {
		n = len(p)
	}
	if w.buffer.Len() >= w.maxBytes+1 {
		return
	}
	remaining := w.maxBytes + 1 - w.buffer.Len()
	if n < remaining {
		remaining = n
	}
	_, _ = w.buffer.Write(p[:remaining])
}

func (w *ResponseWriter) Finalize() {
	w.once.Do(func() {
		if !w.cfg.Enabled || w.span == nil || !w.span.IsRecording() || !w.span.SpanContext().IsSampled() {
			return
		}
		capturePayload(w.span, w.cfg, PayloadStageClientResponse, w.buffer.Bytes(), true)
	})
}

func (w *ResponseWriter) Unwrap() http.ResponseWriter {
	if unwrapper, ok := w.ResponseWriter.(interface{ Unwrap() http.ResponseWriter }); ok {
		return unwrapper.Unwrap()
	}
	return w.ResponseWriter
}
