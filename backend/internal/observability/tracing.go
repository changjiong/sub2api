// Package observability owns the optional OpenTelemetry boundary for gateway
// metadata and explicitly enabled, bounded payload snapshots.
package observability

import (
	"context"
	"errors"
	"io"
	"math"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tidwall/gjson"
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

// Identity is the safe, user-facing ownership context for a gateway request.
// It intentionally carries no token, email, or other credential material.
// Username is used as Phoenix's readable user identifier while the immutable
// numeric identifier remains available as sub2api.user.id.
type Identity struct {
	UserID     int64
	Username   string
	APIKeyID   int64
	APIKeyName string
	GroupID    *int64
	GroupName  string
	Platform   string
	SessionID  string
}

type identityContextKey struct{}
type gatewayModelContextKey struct{}
type gatewayProviderContextKey struct{}
type gatewayRootSpanContextKey struct{}

// WithIdentity carries authenticated ownership through the forwarding context
// so child spans can present the same user and session information as the root.
func WithIdentity(ctx context.Context, identity Identity) context.Context {
	return context.WithValue(ctx, identityContextKey{}, identity)
}

func IdentityFromContext(ctx context.Context) (Identity, bool) {
	identity, ok := ctx.Value(identityContextKey{}).(Identity)
	return identity, ok
}

func WithGatewayModel(ctx context.Context, model string) context.Context {
	model = strings.TrimSpace(model)
	if model == "" {
		return ctx
	}
	return context.WithValue(ctx, gatewayModelContextKey{}, model)
}

func GatewayModelFromContext(ctx context.Context) string {
	model, _ := ctx.Value(gatewayModelContextKey{}).(string)
	return strings.TrimSpace(model)
}

func WithGatewayProvider(ctx context.Context, provider string) context.Context {
	provider = strings.TrimSpace(provider)
	if provider == "" {
		return ctx
	}
	return context.WithValue(ctx, gatewayProviderContextKey{}, provider)
}

func GatewayProviderFromContext(ctx context.Context) string {
	provider, _ := ctx.Value(gatewayProviderContextKey{}).(string)
	return strings.TrimSpace(provider)
}

// gatewaySpan makes EndGatewayRequest safe when a central Gin middleware and a
// legacy endpoint handler both own the same root span during the migration.
type gatewaySpan struct {
	trace.Span
	endOnce sync.Once
}

func (s *gatewaySpan) End(options ...trace.SpanEndOption) {
	if s == nil || s.Span == nil {
		return
	}
	s.endOnce.Do(func() { s.Span.End(options...) })
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
		sdktrace.WithBatcher(
			exporter,
			sdktrace.WithMaxQueueSize(4096),
			sdktrace.WithMaxExportBatchSize(256),
			sdktrace.WithBatchTimeout(time.Second),
		),
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

// StartGatewayRequest starts the root span for a gateway request. A route-level
// middleware may already have started it; handlers then reuse that exact root
// rather than creating a second, disconnected trace.
func StartGatewayRequest(ctx context.Context, endpoint string) (context.Context, trace.Span) {
	if existing, ok := ctx.Value(gatewayRootSpanContextKey{}).(trace.Span); ok && existing != nil {
		return ctx, existing
	}
	startedCtx, span := otel.Tracer(tracerName).Start(ctx, "gateway.request",
		trace.WithSpanKind(trace.SpanKindServer),
		trace.WithAttributes(
			attribute.String("openinference.span.kind", "CHAIN"),
			attribute.String("gateway.endpoint", endpoint),
		),
	)
	wrapped := &gatewaySpan{Span: span}
	startedCtx = trace.ContextWithSpan(startedCtx, wrapped)
	applyGatewayContext(wrapped, startedCtx)
	return context.WithValue(startedCtx, gatewayRootSpanContextKey{}, trace.Span(wrapped)), wrapped
}

// StartGatewayTransform creates the normalization and model-mapping phase below
// an existing gateway request. It never creates an unrelated root trace.
func StartGatewayTransform(ctx context.Context) (context.Context, trace.Span) {
	return startGatewayChild(ctx, "gateway.transform")
}

// StartGatewayRoute creates one account-selection and scheduling phase below an
// existing gateway request. A failover retry gets its own route span.
func StartGatewayRoute(ctx context.Context) (context.Context, trace.Span) {
	return startGatewayChild(ctx, "gateway.route")
}

func startGatewayChild(ctx context.Context, name string) (context.Context, trace.Span) {
	if !trace.SpanContextFromContext(ctx).IsValid() {
		return ctx, nil
	}
	childCtx, span := otel.Tracer(tracerName).Start(ctx, name,
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(attribute.String("openinference.span.kind", "CHAIN")),
	)
	applyGatewayContext(span, childCtx)
	return childCtx, span
}

// SetGatewayIdentity records both Phoenix/OpenInference fields and safe
// Sub2API identifiers. Username is intentionally preferred for user.id so the
// Phoenix list is readable without looking up a numeric database identifier.
func SetGatewayIdentity(span trace.Span, identity Identity) {
	if span == nil {
		return
	}
	attrs := identityAttributes(identity)
	if len(attrs) > 0 {
		span.SetAttributes(attrs...)
	}
}

func identityAttributes(identity Identity) []attribute.KeyValue {
	attrs := make([]attribute.KeyValue, 0, 9)
	if identity.UserID > 0 {
		attrs = append(attrs, attribute.Int64("sub2api.user.id", identity.UserID))
		userID := strings.TrimSpace(identity.Username)
		if userID == "" {
			userID = strconv.FormatInt(identity.UserID, 10)
		}
		attrs = append(attrs,
			attribute.String("user.id", userID),
			attribute.String("user.name", userID),
		)
	}
	if username := strings.TrimSpace(identity.Username); username != "" {
		attrs = append(attrs,
			attribute.String("user.name", username),
			attribute.String("sub2api.user.username", username),
		)
	}
	if identity.APIKeyID > 0 {
		attrs = append(attrs, attribute.Int64("sub2api.api_key.id", identity.APIKeyID))
	}
	if apiKeyName := strings.TrimSpace(identity.APIKeyName); apiKeyName != "" {
		attrs = append(attrs, attribute.String("sub2api.api_key.name", apiKeyName))
	}
	if identity.GroupID != nil && *identity.GroupID > 0 {
		attrs = append(attrs, attribute.Int64("sub2api.group.id", *identity.GroupID))
	}
	if groupName := strings.TrimSpace(identity.GroupName); groupName != "" {
		attrs = append(attrs, attribute.String("sub2api.group.name", groupName))
	}
	if platform := strings.TrimSpace(identity.Platform); platform != "" {
		attrs = append(attrs,
			attribute.String("sub2api.platform", platform),
			attribute.String("gateway.provider", platform),
			attribute.String("llm.provider", platform),
		)
	}
	if sessionID := strings.TrimSpace(identity.SessionID); sessionID != "" {
		attrs = append(attrs, attribute.String("session.id", sessionID))
	}
	return attrs
}

func applyGatewayContext(span trace.Span, ctx context.Context) {
	if span == nil {
		return
	}
	if identity, ok := IdentityFromContext(ctx); ok {
		SetGatewayIdentity(span, identity)
	}
	attrs := make([]attribute.KeyValue, 0, 4)
	if model := GatewayModelFromContext(ctx); model != "" {
		attrs = append(attrs,
			attribute.String("gen_ai.request.model", model),
			attribute.String("llm.model_name", model),
		)
	}
	if provider := GatewayProviderFromContext(ctx); provider != "" {
		attrs = append(attrs,
			attribute.String("gateway.provider", provider),
			attribute.String("llm.provider", provider),
		)
	}
	if len(attrs) > 0 {
		span.SetAttributes(attrs...)
	}
}

// SetGatewayTransformation records only model-level transform metadata. It
// intentionally excludes the request body and headers.
func SetGatewayTransformation(span trace.Span, requestedModel, forwardModel string, mapped bool) {
	if span == nil {
		return
	}
	attrs := []attribute.KeyValue{attribute.Bool("gateway.transform.model_mapped", mapped)}
	if requestedModel = strings.TrimSpace(requestedModel); requestedModel != "" {
		attrs = append(attrs,
			attribute.String("gen_ai.request.model", requestedModel),
			attribute.String("llm.model_name", requestedModel),
		)
	}
	if forwardModel = strings.TrimSpace(forwardModel); forwardModel != "" {
		attrs = append(attrs, attribute.String("gateway.transform.forward_model", forwardModel))
	}
	span.SetAttributes(attrs...)
}

func SetGatewayRequestMetadata(span trace.Span, requestedModel string, stream bool, sessionID, previousResponseID string) {
	if span == nil {
		return
	}
	attrs := []attribute.KeyValue{attribute.Bool("gateway.request.stream", stream)}
	if requestedModel = strings.TrimSpace(requestedModel); requestedModel != "" {
		attrs = append(attrs,
			attribute.String("gen_ai.request.model", requestedModel),
			attribute.String("llm.model_name", requestedModel),
		)
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
	attrs := make([]attribute.KeyValue, 0, 6)
	if accountID > 0 {
		attrs = append(attrs, attribute.Int64("gateway.account.id", accountID))
	}
	if platform = strings.TrimSpace(platform); platform != "" {
		attrs = append(attrs,
			attribute.String("gateway.provider", platform),
			attribute.String("llm.provider", platform),
		)
	}
	if upstreamModel = strings.TrimSpace(upstreamModel); upstreamModel != "" {
		attrs = append(attrs,
			attribute.String("gateway.upstream.model", upstreamModel),
			attribute.String("llm.model_name", upstreamModel),
		)
	}
	if len(attrs) > 0 {
		span.SetAttributes(attrs...)
	}
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
		attribute.Int("gen_ai.usage.input_tokens", result.InputTokens),
		attribute.Int("gen_ai.usage.output_tokens", result.OutputTokens),
		attribute.Int("gen_ai.usage.cache_read_tokens", result.CacheReadTokens),
		attribute.Int("llm.token_count.prompt", result.InputTokens+result.CacheReadTokens),
		attribute.Int("llm.token_count.completion", result.OutputTokens),
		attribute.Int("llm.token_count.total", result.InputTokens+result.CacheReadTokens+result.OutputTokens),
		attribute.Int("llm.token_count.prompt_details.cache_read", result.CacheReadTokens),
		attribute.Int64("gateway.duration_ms", result.Duration.Milliseconds()),
		attribute.Bool("gateway.client_disconnected", result.ClientDisconnect),
	}
	if responseID := strings.TrimSpace(result.ResponseID); responseID != "" {
		attrs = append(attrs, attribute.String("gen_ai.response.id", responseID))
	}
	if requestID := strings.TrimSpace(result.RequestID); requestID != "" {
		attrs = append(attrs, attribute.String("gateway.upstream.request_id", requestID))
	}
	if upstreamModel := strings.TrimSpace(result.UpstreamModel); upstreamModel != "" {
		attrs = append(attrs,
			attribute.String("gen_ai.response.model", upstreamModel),
			attribute.String("llm.model_name", upstreamModel),
		)
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
		} else {
			span.SetStatus(codes.Ok, "")
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
	attrs := []attribute.KeyValue{attribute.String("openinference.span.kind", "LLM")}
	if accountID > 0 {
		attrs = append(attrs, attribute.Int64("gateway.account.id", accountID))
	}
	if req.URL != nil {
		attrs = append(attrs,
			attribute.String("server.address", req.URL.Hostname()),
			attribute.String("url.path", req.URL.EscapedPath()),
		)
	}
	model := GatewayModelFromContext(ctx)
	if model == "" {
		model = providerRequestModel(req)
	}
	if model != "" {
		attrs = append(attrs,
			attribute.String("gen_ai.request.model", model),
			attribute.String("llm.model_name", model),
		)
	}
	if provider := GatewayProviderFromContext(ctx); provider != "" {
		attrs = append(attrs,
			attribute.String("gateway.provider", provider),
			attribute.String("llm.provider", provider),
		)
	}
	attemptCtx, span := otel.Tracer(tracerName).Start(ctx, "provider.attempt",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(attrs...),
	)
	applyGatewayContext(span, attemptCtx)
	return attemptCtx, span
}

func providerRequestModel(req *http.Request) string {
	if req == nil || req.GetBody == nil {
		return ""
	}
	body, err := req.GetBody()
	if err != nil || body == nil {
		return ""
	}
	defer body.Close()
	raw, err := io.ReadAll(io.LimitReader(body, 1<<20))
	if err != nil {
		return ""
	}
	for _, path := range []string{"model", "session.model"} {
		value := gjson.GetBytes(raw, path)
		if value.Type == gjson.String {
			if model := strings.TrimSpace(value.String()); model != "" {
				return model
			}
		}
	}
	return ""
}

func EndProviderAttempt(span trace.Span, response *http.Response, err error) {
	if span == nil {
		return
	}
	if response != nil {
		span.SetAttributes(attribute.Int("http.response.status_code", response.StatusCode))
		if response.StatusCode >= http.StatusBadRequest {
			span.SetStatus(codes.Error, "upstream request failed")
		} else {
			span.SetStatus(codes.Ok, "")
		}
	}
	if err != nil {
		RecordError(span, err)
	} else if response == nil {
		span.SetStatus(codes.Error, "upstream response missing")
	}
	span.End()
}
