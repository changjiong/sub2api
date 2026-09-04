package observability

import (
	"strings"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/trace"
)

// GatewayMiddleware creates one reusable root span for every gateway route.
// Authentication and forwarding continue in the normal Gin chain; payload
// capture is a bounded tee of bytes those handlers already read or write.
func GatewayMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request == nil || !isGatewayPath(c.Request.URL.Path) {
			c.Next()
			return
		}
		if _, exists := c.Request.Context().Value(gatewayRootSpanContextKey{}).(trace.Span); exists {
			c.Next()
			return
		}

		traceCtx, requestSpan := StartGatewayRequest(c.Request.Context(), c.Request.URL.Path)
		c.Request = c.Request.WithContext(traceCtx)

		var requestRecorder *RequestBodyRecorder
		if shouldRecordGatewayRequest(c) && requestSpan != nil && requestSpan.IsRecording() && requestSpan.SpanContext().IsSampled() {
			requestRecorder = NewRequestBodyRecorder(c.Request.Body, requestSpan)
			c.Request.Body = requestRecorder
		}

		originalWriter := c.Writer
		responseWriter := NewResponseWriter(originalWriter, requestSpan)
		c.Writer = responseWriter

		c.Next()

		if requestRecorder != nil {
			requestRecorder.Finalize()
		}
		responseWriter.Finalize()
		EndGatewayRequest(requestSpan, c.Writer.Status())
		if c.Writer == responseWriter {
			c.Writer = originalWriter
		}
	}
}

func isGatewayPath(path string) bool {
	path = strings.TrimSpace(path)
	for _, prefix := range []string{
		"/v1",
		"/v1beta",
		"/responses",
		"/backend-api/codex",
		"/chat/completions",
		"/embeddings",
		"/messages",
		"/images",
		"/videos",
		"/tts",
		"/stt",
		"/custom-voices",
		"/realtime",
		"/web_search",
		"/x_search",
		"/antigravity",
	} {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	return false
}

func shouldRecordGatewayRequest(c *gin.Context) bool {
	if c == nil || c.Request == nil || c.Request.Body == nil || c.Request.ContentLength == 0 {
		return false
	}
	contentType := strings.ToLower(strings.TrimSpace(c.GetHeader("Content-Type")))
	// Multipart uploads are represented by attachment events and storage state,
	// not body snapshots. This keeps binary file bytes out of the trace.
	return !strings.HasPrefix(contentType, "multipart/")
}
