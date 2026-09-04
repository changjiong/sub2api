package observability

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"

	"go.opentelemetry.io/otel/trace"
)

// AttachmentRole describes whether an attachment entered or left the gateway.
// It deliberately does not describe a provider-specific message format.
type AttachmentRole string

const (
	AttachmentRoleUnknown AttachmentRole = "unknown"
	AttachmentRoleInput   AttachmentRole = "input"
	AttachmentRoleOutput  AttachmentRole = "output"
)

// AttachmentKind is intentionally small. Protocol adapters may add more
// metadata later without making the storage or tracing contracts provider-aware.
type AttachmentKind string

const (
	AttachmentKindFile  AttachmentKind = "file"
	AttachmentKindImage AttachmentKind = "image"
)

type AttachmentSource string

const (
	AttachmentSourceInlineBase64 AttachmentSource = "inline_base64"
	AttachmentSourceGatewayFile  AttachmentSource = "gateway_file"
)

const attachmentEventName = "gateway.attachment"

// AttachmentStorageState makes it explicit that payload sanitization has not
// persisted any content. A later asynchronous storage worker can move the
// manifest through queued, stored, skipped, or failed without changing the
// payload-capture contract.
type AttachmentStorageState string

const (
	AttachmentStorageMetadataOnly AttachmentStorageState = "metadata_only"
	AttachmentStorageQueued       AttachmentStorageState = "queued"
	AttachmentStorageStored       AttachmentStorageState = "stored"
	AttachmentStorageSkipped      AttachmentStorageState = "skipped"
	AttachmentStorageFailed       AttachmentStorageState = "failed"
)

// AttachmentManifest is safe to export as trace metadata: it contains no
// attachment bytes, data URL, remote URL, credential, or object-store key.
// ByteSize is -1 when an inline value was not valid Base64 and therefore could
// not be decoded safely for metadata extraction.
type AttachmentManifest struct {
	ID           string                 `json:"id"`
	Stage        string                 `json:"stage"`
	Role         AttachmentRole         `json:"role"`
	Kind         AttachmentKind         `json:"kind"`
	MIMEType     string                 `json:"mime_type"`
	Filename     string                 `json:"filename,omitempty"`
	ByteSize     int64                  `json:"byte_size"`
	SHA256       string                 `json:"sha256,omitempty"`
	Source       AttachmentSource       `json:"source"`
	StorageState AttachmentStorageState `json:"storage_state"`
	ViewerPath   string                 `json:"viewer_path,omitempty"`
}

// AttachmentCollector is a metadata-only extension boundary. It intentionally
// does not carry an io.Reader: capture code must never make object storage part
// of the request forwarding path.
type AttachmentCollector interface {
	CollectAttachment(ctx context.Context, manifest AttachmentManifest) error
}

// AttachmentCollectorFunc adapts a function to AttachmentCollector.
type AttachmentCollectorFunc func(ctx context.Context, manifest AttachmentManifest) error

func (f AttachmentCollectorFunc) CollectAttachment(ctx context.Context, manifest AttachmentManifest) error {
	return f(ctx, manifest)
}

// RecordInlineAttachmentManifests emits attachment metadata for inline media
// found in a captured JSON or SSE payload. If a private storage runtime is
// configured, valid Base64 is offered to its bounded queue without waiting for
// object storage; the initial event therefore records queued or skipped. The
// worker later adds a stored/failed event on the same trace.
func RecordInlineAttachmentManifests(span trace.Span, stage PayloadStage, raw []byte) {
	if span == nil || !span.IsRecording() || !span.SpanContext().IsSampled() || len(raw) == 0 {
		return
	}
	runtime := configuredAttachmentRuntime.Load()
	seen := make(map[string]struct{})
	for _, candidate := range extractInlineAttachmentCandidates(stage, raw) {
		manifest := candidate.manifest
		key := manifest.ID + "\x00" + manifest.Stage
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		reason := ""
		if runtime != nil {
			manifest.StorageState, reason = runtime.enqueueInline(manifest, candidate.encoded, span.SpanContext())
			if manifest.StorageState == AttachmentStorageQueued {
				manifest.ViewerPath = AttachmentViewerPath(manifest.ID)
			}
		}
		span.AddEvent(attachmentEventName, trace.WithAttributes(attachmentAttributes(manifest, reason)...))
	}
}

// ExtractInlineAttachmentManifests walks JSON and SSE data frames and returns
// metadata for supported inline media fields. It is intentionally independent
// of object storage so the request forwarding path never waits on persistence.
func ExtractInlineAttachmentManifests(stage PayloadStage, raw []byte) []AttachmentManifest {
	candidates := extractInlineAttachmentCandidates(stage, raw)
	manifests := make([]AttachmentManifest, 0, len(candidates))
	for _, candidate := range candidates {
		manifests = append(manifests, candidate.manifest)
	}
	return manifests
}

type inlineAttachmentCandidate struct {
	manifest AttachmentManifest
	encoded  string
}

func extractInlineAttachmentCandidates(stage PayloadStage, raw []byte) []inlineAttachmentCandidate {
	if bytes.Contains(raw, []byte("data:")) || bytes.Contains(raw, []byte("event:")) {
		var candidates []inlineAttachmentCandidate
		for _, frame := range bytes.Split(raw, []byte("\n\n")) {
			for _, line := range bytes.Split(frame, []byte("\n")) {
				line = bytes.TrimSuffix(line, []byte("\r"))
				if !bytes.HasPrefix(line, []byte("data:")) {
					continue
				}
				value := bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
				if bytes.Equal(value, []byte("[DONE]")) {
					continue
				}
				candidates = append(candidates, extractInlineAttachmentCandidatesJSON(stage, value)...)
			}
		}
		// A normal JSON request can itself contain a data: URL. Only treat the
		// input as SSE when it actually yielded data frames; otherwise fall back
		// to the JSON walker below.
		if len(candidates) > 0 || bytes.Contains(raw, []byte("\ndata:")) || bytes.HasPrefix(bytes.TrimSpace(raw), []byte("data:")) {
			return candidates
		}
	}
	return extractInlineAttachmentCandidatesJSON(stage, raw)
}

func extractInlineAttachmentManifestsJSON(stage PayloadStage, raw []byte) []AttachmentManifest {
	candidates := extractInlineAttachmentCandidatesJSON(stage, raw)
	manifests := make([]AttachmentManifest, 0, len(candidates))
	for _, candidate := range candidates {
		manifests = append(manifests, candidate.manifest)
	}
	return manifests
}

func extractInlineAttachmentCandidatesJSON(stage PayloadStage, raw []byte) []inlineAttachmentCandidate {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil
	}
	var candidates []inlineAttachmentCandidate
	collectInlineAttachmentCandidates(stage, value, &candidates)
	return candidates
}

func collectInlineAttachmentManifests(stage PayloadStage, value any, manifests *[]AttachmentManifest) {
	var candidates []inlineAttachmentCandidate
	collectInlineAttachmentCandidates(stage, value, &candidates)
	for _, candidate := range candidates {
		*manifests = append(*manifests, candidate.manifest)
	}
}

func collectInlineAttachmentCandidates(stage PayloadStage, value any, candidates *[]inlineAttachmentCandidate) {
	switch typed := value.(type) {
	case map[string]any:
		for key, item := range typed {
			if stringValue, ok := item.(string); ok {
				if manifest, found := ExtractInlineAttachmentManifest(string(stage), key, stringValue); found {
					*candidates = append(*candidates, inlineAttachmentCandidate{
						manifest: manifest,
						encoded:  encodedInlineAttachmentValue(key, stringValue),
					})
					continue
				}
			}
			collectInlineAttachmentCandidates(stage, item, candidates)
		}
	case []any:
		for _, item := range typed {
			collectInlineAttachmentCandidates(stage, item, candidates)
		}
	}
}

func encodedInlineAttachmentValue(field, value string) string {
	if _, encoded, ok := splitBase64DataURL(value); ok {
		return encoded
	}
	return strings.TrimSpace(value)
}

// PayloadReference is the JSON-safe substitute for an inline attachment in a
// captured gateway payload. It intentionally never includes ViewerPath: a
// future viewer must be authorized separately rather than exposing a durable
// link through trace data.
func (m AttachmentManifest) PayloadReference() map[string]any {
	reference := map[string]any{
		"attachment_id": m.ID,
		"kind":          m.Kind,
		"mime_type":     m.MIMEType,
		"byte_size":     m.ByteSize,
		"source":        m.Source,
		"storage_state": m.StorageState,
	}
	if m.SHA256 != "" {
		reference["sha256"] = m.SHA256
	}
	return map[string]any{"attachment_ref": reference}
}

// ExtractInlineAttachmentManifest recognizes the inline media representations
// used by Responses and Images payloads. It returns metadata only; the source
// value is never retained or returned. Invalid Base64 is still replaced so a
// malformed attachment cannot leak into Phoenix.
func ExtractInlineAttachmentManifest(stage, field, value string) (AttachmentManifest, bool) {
	field = normalizeAttachmentField(field)
	switch field {
	case "imageurl":
		mimeType, encoded, ok := splitBase64DataURL(value)
		if !ok || !strings.HasPrefix(mimeType, "image/") {
			return AttachmentManifest{}, false
		}
		return newInlineAttachmentManifest(stage, AttachmentKindImage, mimeType, encoded), true
	case "filedata":
		mimeType, encoded, ok := splitBase64DataURL(value)
		if !ok {
			mimeType = "application/octet-stream"
			encoded = value
		}
		return newInlineAttachmentManifest(stage, AttachmentKindFile, mimeType, encoded), true
	case "b64json", "partialimageb64":
		mimeType, encoded, ok := splitBase64DataURL(value)
		if !ok {
			mimeType = "image/*"
			encoded = value
		}
		return newInlineAttachmentManifest(stage, AttachmentKindImage, mimeType, encoded), true
	default:
		return AttachmentManifest{}, false
	}
}

func newInlineAttachmentManifest(stage string, kind AttachmentKind, mimeType, encoded string) AttachmentManifest {
	sha256Value, byteSize, valid := base64Digest(encoded)
	if !valid {
		invalidSum := sha256.Sum256([]byte(encoded))
		return AttachmentManifest{
			ID:           attachmentID(hex.EncodeToString(invalidSum[:])),
			Stage:        strings.TrimSpace(stage),
			Role:         attachmentRoleForStage(stage),
			Kind:         kind,
			MIMEType:     mimeType,
			ByteSize:     -1,
			Source:       AttachmentSourceInlineBase64,
			StorageState: AttachmentStorageMetadataOnly,
		}
	}
	return AttachmentManifest{
		ID:           attachmentID(sha256Value),
		Stage:        strings.TrimSpace(stage),
		Role:         attachmentRoleForStage(stage),
		Kind:         kind,
		MIMEType:     mimeType,
		ByteSize:     byteSize,
		SHA256:       sha256Value,
		Source:       AttachmentSourceInlineBase64,
		StorageState: AttachmentStorageMetadataOnly,
	}
}

func attachmentID(digest string) string {
	if len(digest) > 24 {
		digest = digest[:24]
	}
	return "att_" + digest
}

func attachmentRoleForStage(stage string) AttachmentRole {
	switch {
	case strings.HasSuffix(strings.ToLower(strings.TrimSpace(stage)), ".request"):
		return AttachmentRoleInput
	case strings.HasSuffix(strings.ToLower(strings.TrimSpace(stage)), ".response"):
		return AttachmentRoleOutput
	default:
		return AttachmentRoleUnknown
	}
}

func normalizeAttachmentField(field string) string {
	replacer := strings.NewReplacer("_", "", "-", "", " ", "")
	return replacer.Replace(strings.ToLower(strings.TrimSpace(field)))
}

func splitBase64DataURL(value string) (mimeType, encoded string, ok bool) {
	header, encoded, found := strings.Cut(strings.TrimSpace(value), ",")
	if !found || !strings.HasPrefix(strings.ToLower(header), "data:") {
		return "", "", false
	}
	parts := strings.Split(header[len("data:"):], ";")
	if len(parts) == 0 {
		return "", "", false
	}
	mimeType = strings.ToLower(strings.TrimSpace(parts[0]))
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}
	for _, part := range parts[1:] {
		if strings.EqualFold(strings.TrimSpace(part), "base64") {
			return mimeType, encoded, true
		}
	}
	return "", "", false
}

func base64Digest(encoded string) (string, int64, bool) {
	encoded = strings.TrimSpace(encoded)
	encodings := []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding}
	if strings.ContainsAny(encoded, "-_") {
		encodings = []*base64.Encoding{base64.URLEncoding, base64.RawURLEncoding}
	}
	for _, encoding := range encodings {
		hash := sha256.New()
		byteSize, err := io.Copy(hash, base64.NewDecoder(encoding, strings.NewReader(encoded)))
		if err == nil {
			return hex.EncodeToString(hash.Sum(nil)), byteSize, true
		}
	}
	return "", -1, false
}
