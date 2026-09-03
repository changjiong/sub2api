// Package observability owns the optional OpenTelemetry boundary for gateway
// metadata and explicitly enabled, bounded payload snapshots.
package observability

import (
	"context"
	"errors"
	"math"
	"net/http"
	"reflect"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

const (
	tracerName         = "github.com/Wei-Shaw/sub2api/gateway"
	defaultServiceName = "sub2api"
	defaultSampleRatio = 1.0
)

type Config struct {
	Enabled         bool
	Endpoint        string
	SampleRatio     float64
	ServiceName     string
	CapturePayload  bool
	MaxPayloadBytes int
}

// Provider owns the SDK lifecycle. A nil provider is a no-op instance.
type Provider struct {
	tracerProvider *sdktrace.TracerProvider
}

// Init installs an OTLP/HTTP batch exporter when observability is enabled. The
// exporter is asynchronous: an unavailable collector never makes a model request
// wait for or depend on Phoenix.
func Init(ctx context.Context, cfg Config, serviceVersion string) (*Provider, error) {
	provider := &Provider{}
	ConfigurePayloadCapture(PayloadCaptureConfig{
		Enabled:  cfg.Enabled && cfg.CapturePayload,
		MaxBytes: cfg.MaxPayloadBytes,
	})
	if !cfg.Enabled {
		return provider, nil
	}

	endpoint := strings.TrimSpace(cfg.Endpoint)
	if endpoint == "" {
		return provider, errors.New("observability.otlp_traces_endpoint is required when observability is enabled")
	}
	exporterOptions := []otlptracehttp.Option{otlptracehttp.WithEndpointURL(endpoint)}
	exporter, err := otlptracehttp.New(ctx, exporterOptions...)
	if err != nil {
		return provider, err
	}

	serviceName := strings.TrimSpace(cfg.ServiceName)
	if serviceName == "" {
		serviceName = defaultServiceName
	}
	sampleRatio := cfg.SampleRatio
	if math.IsNaN(sampleRatio) || sampleRatio < 0 || sampleRatio > 1 {
		sampleRatio = defaultSampleRatio
	}

	provider.tracerProvider = sdktrace.NewTracerProvider(
		sdktrace.WithResource(resource.NewWithAttributes("",
			attribute.String("service.name", serviceName),
			attribute.String("service.version", strings.TrimSpace(serviceVersion)),
		)),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(sampleRatio))),
		// Keep exports asynchronous so an unavailable Phoenix never blocks a model
		// request. The payload policy is applied before events reach this exporter.
		sdktrace.WithBatcher(exporter),
	)
	otel.SetTracerProvider(provider.tracerProvider)
	return provider, nil
}

// Shutdown drains accepted spans within the caller's bounded shutdown context.
func (p *Provider) Shutdown(ctx context.Context) error {
	if p == nil || p.tracerProvider == nil {
		return nil
	}
	return p.tracerProvider.Shutdown(ctx)
}

// StartGatewayRequest starts the root span for an OpenAI Responses request. It
// only records explicit metadata passed by the handler; it never reads the body
// or headers itself.
func StartGatewayRequest(ctx context.Context, endpoint string) (context.Context, trace.Span) {
	return otel.Tracer(tracerName).Start(ctx, "gateway.request",
		trace.WithSpanKind(trace.SpanKindServer),
		trace.WithAttributes(attribute.String("gateway.endpoint", endpoint)),
	)
}

func SetGatewayRequestMetadata(span trace.Span, requestedModel string, stream bool, sessionID, previousResponseID string) {
	if span == nil {
		return
	}
	attrs := []attribute.KeyValue{
		attribute.String("gen_ai.request.model", strings.TrimSpace(requestedModel)),
		attribute.Bool("gateway.request.stream", stream),
	}
	if sessionID = strings.TrimSpace(sessionID); sessionID != "" {
		attrs = append(attrs, attribute.String("session.id", sessionID))
	}
	if previousResponseID = strings.TrimSpace(previousResponseID); previousResponseID != "" {
		attrs = append(attrs, attribute.String("gen_ai.response.previous_id", previousResponseID))
	}
	span.SetAttributes(attrs...)
}

func SetGatewayRouting(span trace.Span, accountID int64, platform, upstreamModel string) {
	if span == nil {
		return
	}
	span.SetAttributes(
		attribute.Int64("gateway.account.id", accountID),
		attribute.String("gateway.provider", strings.TrimSpace(platform)),
		attribute.String("gateway.upstream.model", strings.TrimSpace(upstreamModel)),
	)
}

type GatewayResult struct {
	RequestID        string
	ResponseID       string
	UpstreamModel    string
	InputTokens      int
	OutputTokens     int
	CacheReadTokens  int
	Duration         time.Duration
	FirstTokenMs     *int
	ClientDisconnect bool
}

func SetGatewayResult(span trace.Span, result GatewayResult) {
	if span == nil {
		return
	}
	attrs := []attribute.KeyValue{
		attribute.String("gen_ai.response.id", strings.TrimSpace(result.ResponseID)),
		attribute.String("gateway.upstream.request_id", strings.TrimSpace(result.RequestID)),
		attribute.String("gen_ai.response.model", strings.TrimSpace(result.UpstreamModel)),
		attribute.Int("gen_ai.usage.input_tokens", result.InputTokens),
		attribute.Int("gen_ai.usage.output_tokens", result.OutputTokens),
		attribute.Int("gen_ai.usage.cache_read_tokens", result.CacheReadTokens),
		attribute.Int64("gateway.duration_ms", result.Duration.Milliseconds()),
		attribute.Bool("gateway.client_disconnected", result.ClientDisconnect),
	}
	if result.FirstTokenMs != nil {
		attrs = append(attrs, attribute.Int("gen_ai.time_to_first_token_ms", *result.FirstTokenMs))
	}
	span.SetAttributes(attrs...)
}

// RecordError stores the error class, never its raw message: upstream messages
// can contain request excerpts or provider-specific sensitive diagnostics.
func RecordError(span trace.Span, err error) {
	if span == nil || err == nil {
		return
	}
	typeName := reflect.TypeOf(err).String()
	if typeName == "" {
		typeName = "error"
	}
	span.SetAttributes(attribute.String("error.type", typeName))
	span.SetStatus(codes.Error, "request failed")
}

func EndGatewayRequest(span trace.Span, statusCode int) {
	if span == nil {
		return
	}
	if statusCode > 0 {
		span.SetAttributes(attribute.Int("http.response.status_code", statusCode))
		if statusCode >= http.StatusBadRequest {
			span.SetStatus(codes.Error, "request failed")
		}
	}
	span.End()
}

// StartProviderAttempt creates a child span only when the caller already has a
// gateway trace. This prevents unrelated upstream HTTP traffic from becoming a
// new root trace.
func StartProviderAttempt(ctx context.Context, req *http.Request, accountID int64) (context.Context, trace.Span) {
	if req == nil || !trace.SpanContextFromContext(ctx).IsValid() {
		return ctx, nil
	}
	attrs := []attribute.KeyValue{attribute.Int64("gateway.account.id", accountID)}
	if req.URL != nil {
		attrs = append(attrs,
			attribute.String("server.address", req.URL.Hostname()),
			attribute.String("url.path", req.URL.EscapedPath()),
		)
	}
	return otel.Tracer(tracerName).Start(ctx, "provider.attempt",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(attrs...),
	)
}

func EndProviderAttempt(span trace.Span, response *http.Response, err error) {
	if span == nil {
		return
	}
	if response != nil {
		span.SetAttributes(attribute.Int("http.response.status_code", response.StatusCode))
		if response.StatusCode >= http.StatusBadRequest {
			span.SetStatus(codes.Error, "upstream request failed")
		}
	}
	if err != nil {
		RecordError(span, err)
	}
	span.End()
}
