package observability

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"path"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

const (
	defaultAttachmentQueueSize     = 16
	defaultAttachmentWorkerCount   = 2
	defaultAttachmentMaxBytes      = int64(32 << 20) // 32 MiB per decoded attachment
	defaultAttachmentMaxQueueBytes = int64(128 << 20)
	defaultAttachmentUploadTimeout = 45 * time.Second
	attachmentViewerBasePath       = "/api/v1/admin/observability/attachments"
)

var (
	// ErrAttachmentNotFound lets a controlled viewer distinguish a missing
	// object from an unavailable object store without exposing backend errors.
	ErrAttachmentNotFound = errors.New("observability attachment not found")
	// ErrAttachmentStorageUnavailable is returned when attachment persistence
	// has not been configured for the current process.
	ErrAttachmentStorageUnavailable = errors.New("observability attachment storage is unavailable")
	attachmentIDPattern             = regexp.MustCompile(`^att_[0-9a-f]{24}$`)
	configuredAttachmentRuntime     atomic.Pointer[AttachmentRuntime]
)

// AttachmentObject is the provider-independent object metadata required for
// a private object store. The object key is never exported to Phoenix.
type AttachmentObject struct {
	Key         string
	ContentType string
	Filename    string
	Size        int64
}

// AttachmentObjectInfo is safe to return from Head/Get. It contains no
// provider URL, credentials, or bucket information.
type AttachmentObjectInfo struct {
	ContentType string
	Filename    string
	Size        int64
}

// AttachmentStorage is deliberately a controlled-read contract. It does not
// expose presigned URLs, so Phoenix only stores the stable Sub2API viewer path.
type AttachmentStorage interface {
	Put(ctx context.Context, object AttachmentObject, body io.Reader) error
	Head(ctx context.Context, key string) (AttachmentObjectInfo, error)
	Get(ctx context.Context, key string) (io.ReadCloser, AttachmentObjectInfo, error)
}

// AttachmentRuntimeConfig bounds the in-process work admitted by payload
// capture. These bounds protect the gateway independently of object-store
// quota, which is enforced by the private MinIO/S3 deployment.
type AttachmentRuntimeConfig struct {
	QueueSize       int
	WorkerCount     int
	MaxBytes        int64
	MaxQueuedBytes  int64
	UploadTimeout   time.Duration
	ObjectKeyPrefix string
}

// AttachmentRuntime owns a bounded, asynchronous persistence queue. A caller
// never waits for object storage: enqueue either succeeds immediately or
// returns a terminal skipped state.
type AttachmentRuntime struct {
	storage AttachmentStorage
	cfg     AttachmentRuntimeConfig

	ctx    context.Context
	cancel context.CancelFunc
	queue  chan attachmentJob

	queuedBytes atomic.Int64
	stopOnce    sync.Once
	done        chan struct{}
	wg          sync.WaitGroup
}

type attachmentJob struct {
	manifest AttachmentManifest
	encoded  string
	data     []byte
	parent   trace.SpanContext
}

// NewAttachmentRuntime starts the bounded workers. A nil storage is rejected
// so no caller can accidentally claim persistence without a private store.
func NewAttachmentRuntime(storage AttachmentStorage, cfg AttachmentRuntimeConfig) (*AttachmentRuntime, error) {
	if storage == nil {
		return nil, errors.New("observability attachment storage is nil")
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = defaultAttachmentQueueSize
	}
	if cfg.WorkerCount <= 0 {
		cfg.WorkerCount = defaultAttachmentWorkerCount
	}
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = defaultAttachmentMaxBytes
	}
	if cfg.MaxQueuedBytes <= 0 {
		cfg.MaxQueuedBytes = defaultAttachmentMaxQueueBytes
	}
	if cfg.UploadTimeout <= 0 {
		cfg.UploadTimeout = defaultAttachmentUploadTimeout
	}
	cfg.ObjectKeyPrefix = normalizeAttachmentKeyPrefix(cfg.ObjectKeyPrefix)

	ctx, cancel := context.WithCancel(context.Background())
	runtime := &AttachmentRuntime{
		storage: storage,
		cfg:     cfg,
		ctx:     ctx,
		cancel:  cancel,
		queue:   make(chan attachmentJob, cfg.QueueSize),
		done:    make(chan struct{}),
	}
	for range cfg.WorkerCount {
		runtime.wg.Add(1)
		go runtime.runWorker()
	}
	go func() {
		runtime.wg.Wait()
		close(runtime.done)
	}()
	return runtime, nil
}

// ConfigureAttachmentRuntime installs the process-wide optional runtime used
// by payload capture and the authenticated viewer. It is configured exactly
// once at startup; replacing a live runtime is intentionally unsupported.
func ConfigureAttachmentRuntime(runtime *AttachmentRuntime) {
	configuredAttachmentRuntime.Store(runtime)
}

// AttachmentViewerPath is the only durable attachment locator that may be
// sent to Phoenix. It stays behind the normal Sub2API administrator middleware.
func AttachmentViewerPath(id string) string {
	if !validAttachmentID(id) {
		return ""
	}
	return attachmentViewerBasePath + "/" + id + "/preview"
}

// OpenAttachment serves the controlled viewer. It never returns an object
// store URL or key and validates the opaque attachment ID before looking up an
// object.
func OpenAttachment(ctx context.Context, id string) (io.ReadCloser, AttachmentObjectInfo, error) {
	if !validAttachmentID(id) {
		return nil, AttachmentObjectInfo{}, ErrAttachmentNotFound
	}
	runtime := configuredAttachmentRuntime.Load()
	if runtime == nil {
		return nil, AttachmentObjectInfo{}, ErrAttachmentStorageUnavailable
	}
	return runtime.storage.Get(ctx, runtime.objectKey(id))
}

// Shutdown cancels pending object-store work and waits only until ctx expires.
// It must run before the OTLP provider shuts down so final failed states can be
// exported while telemetry remains available.
func (r *AttachmentRuntime) Shutdown(ctx context.Context) error {
	if r == nil {
		return nil
	}
	r.stopOnce.Do(func() {
		r.cancel()
		close(r.queue)
	})
	select {
	case <-r.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// enqueueInline schedules one already-classified inline source. It is called
// from payload capture and never blocks on a full queue or object store.
func (r *AttachmentRuntime) enqueueInline(manifest AttachmentManifest, encoded string, parent trace.SpanContext) (AttachmentStorageState, string) {
	if r == nil || !parent.IsValid() || !parent.IsSampled() {
		return AttachmentStorageMetadataOnly, "storage_unavailable"
	}
	if manifest.ByteSize < 0 || manifest.SHA256 == "" {
		return AttachmentStorageSkipped, "invalid_base64"
	}
	if manifest.ByteSize > r.cfg.MaxBytes {
		return AttachmentStorageSkipped, "attachment_too_large"
	}
	queuedBytes := int64(len(encoded))
	if queuedBytes <= 0 {
		return AttachmentStorageSkipped, "empty_attachment"
	}
	if !r.reserveQueueBytes(queuedBytes) {
		return AttachmentStorageSkipped, "queue_byte_limit"
	}

	job := attachmentJob{manifest: manifest, encoded: encoded, parent: parent}
	return r.enqueueJob(job, queuedBytes)
}

// RecordBinaryAttachment queues a multipart/file attachment without forcing it
// through JSON or Base64. The caller only pays the metadata/hash work and a
// bounded copy; object storage is still written by the background workers.
func RecordBinaryAttachment(span trace.Span, stage PayloadStage, kind AttachmentKind, mimeType, filename string, data []byte) {
	if span == nil || !span.IsRecording() || !span.SpanContext().IsSampled() || len(data) == 0 {
		return
	}
	manifest := NewBinaryAttachmentManifest(stage, kind, mimeType, filename, data)
	runtime := configuredAttachmentRuntime.Load()
	if runtime == nil {
		span.AddEvent(attachmentEventName, trace.WithAttributes(attachmentAttributes(manifest, "storage_unavailable")...))
		return
	}
	state, reason := runtime.enqueueBytes(manifest, data, span.SpanContext())
	manifest.StorageState = state
	if state == AttachmentStorageQueued {
		manifest.ViewerPath = AttachmentViewerPath(manifest.ID)
	}
	span.AddEvent(attachmentEventName, trace.WithAttributes(attachmentAttributes(manifest, reason)...))
}

// NewBinaryAttachmentManifest creates metadata for a multipart or already
// decoded file. The bytes are never put in a span event.
func NewBinaryAttachmentManifest(stage PayloadStage, kind AttachmentKind, mimeType, filename string, data []byte) AttachmentManifest {
	digest := sha256.Sum256(data)
	return AttachmentManifest{
		ID:           attachmentID(hex.EncodeToString(digest[:])),
		Stage:        string(stage),
		Role:         attachmentRoleForStage(string(stage)),
		Kind:         kind,
		MIMEType:     strings.TrimSpace(mimeType),
		Filename:     strings.TrimSpace(filename),
		ByteSize:     int64(len(data)),
		SHA256:       hex.EncodeToString(digest[:]),
		Source:       AttachmentSource("multipart"),
		StorageState: AttachmentStorageMetadataOnly,
	}
}

func (r *AttachmentRuntime) enqueueBytes(manifest AttachmentManifest, data []byte, parent trace.SpanContext) (AttachmentStorageState, string) {
	if r == nil || !parent.IsValid() || !parent.IsSampled() {
		return AttachmentStorageMetadataOnly, "storage_unavailable"
	}
	if len(data) == 0 {
		return AttachmentStorageSkipped, "empty_attachment"
	}
	if int64(len(data)) > r.cfg.MaxBytes {
		return AttachmentStorageSkipped, "attachment_too_large"
	}
	copyData := append([]byte(nil), data...)
	queuedBytes := int64(len(copyData))
	if !r.reserveQueueBytes(queuedBytes) {
		return AttachmentStorageSkipped, "queue_byte_limit"
	}
	return r.enqueueJob(attachmentJob{manifest: manifest, data: copyData, parent: parent}, queuedBytes)
}

func (r *AttachmentRuntime) reserveQueueBytes(n int64) bool {
	if n <= 0 {
		return false
	}
	for {
		current := r.queuedBytes.Load()
		if current+n > r.cfg.MaxQueuedBytes {
			return false
		}
		if r.queuedBytes.CompareAndSwap(current, current+n) {
			return true
		}
	}
}

func (r *AttachmentRuntime) enqueueJob(job attachmentJob, queuedBytes int64) (AttachmentStorageState, string) {
	select {
	case r.queue <- job:
		return AttachmentStorageQueued, ""
	default:
		r.queuedBytes.Add(-queuedBytes)
		return AttachmentStorageSkipped, "queue_full"
	}
}

func (r *AttachmentRuntime) runWorker() {
	defer r.wg.Done()
	for job := range r.queue {
		queuedBytes := int64(len(job.encoded))
		if len(job.data) > 0 {
			queuedBytes = int64(len(job.data))
		}
		r.queuedBytes.Add(-queuedBytes)
		state, reason := r.persist(job)
		r.recordPersistence(job.manifest, job.parent, state, reason)
	}
}

func (r *AttachmentRuntime) persist(job attachmentJob) (AttachmentStorageState, string) {
	if err := r.ctx.Err(); err != nil {
		return AttachmentStorageSkipped, "shutdown"
	}
	ctx, cancel := context.WithTimeout(r.ctx, r.cfg.UploadTimeout)
	defer cancel()

	key := r.objectKey(job.manifest.ID)
	if _, err := r.storage.Head(ctx, key); err == nil {
		return AttachmentStorageStored, "already_exists"
	} else if !errors.Is(err, ErrAttachmentNotFound) {
		return AttachmentStorageFailed, "storage_head_failed"
	}

	var contentType string
	var reader io.Reader
	if len(job.data) > 0 {
		contentType = strings.TrimSpace(job.manifest.MIMEType)
		reader = bytes.NewReader(job.data)
	} else {
		decoder := base64.NewDecoder(selectBase64Encoding(job.encoded), strings.NewReader(trimBase64Padding(job.encoded)))
		var err error
		contentType, reader, err = preparedAttachmentReader(decoder, job.manifest.MIMEType)
		if err != nil {
			return AttachmentStorageFailed, "base64_decode_failed"
		}
	}
	if !isSafeAttachmentContentType(contentType) {
		contentType = "application/octet-stream"
	}
	object := AttachmentObject{
		Key:         key,
		ContentType: contentType,
		Filename:    attachmentFilename(job.manifest, contentType),
		Size:        job.manifest.ByteSize,
	}
	if err := r.storage.Put(ctx, object, io.LimitReader(reader, r.cfg.MaxBytes+1)); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return AttachmentStorageFailed, "storage_timeout"
		}
		return AttachmentStorageFailed, "storage_put_failed"
	}
	return AttachmentStorageStored, ""
}

func (r *AttachmentRuntime) recordPersistence(manifest AttachmentManifest, parent trace.SpanContext, state AttachmentStorageState, reason string) {
	ctx := trace.ContextWithSpanContext(context.Background(), parent)
	_, span := otel.Tracer(tracerName).Start(ctx, attachmentEventName, trace.WithSpanKind(trace.SpanKindInternal))
	defer span.End()

	manifest.StorageState = state
	if state == AttachmentStorageStored {
		manifest.ViewerPath = AttachmentViewerPath(manifest.ID)
	}
	attrs := attachmentAttributes(manifest, reason)
	span.SetAttributes(attrs...)
	span.AddEvent(attachmentEventName, trace.WithAttributes(attrs...))
}

func (r *AttachmentRuntime) objectKey(id string) string {
	return r.cfg.ObjectKeyPrefix + id
}

func normalizeAttachmentKeyPrefix(prefix string) string {
	prefix = strings.TrimSpace(prefix)
	prefix = strings.Trim(prefix, "/")
	if prefix == "" {
		return "attachments/"
	}
	prefix = path.Clean(prefix)
	prefix = strings.Trim(prefix, "/")
	if prefix == "." || strings.HasPrefix(prefix, "..") {
		return "attachments/"
	}
	return prefix + "/"
}

func validAttachmentID(id string) bool {
	return attachmentIDPattern.MatchString(strings.TrimSpace(id))
}

func selectBase64Encoding(encoded string) *base64.Encoding {
	if strings.ContainsAny(encoded, "-_") {
		return base64.RawURLEncoding
	}
	return base64.RawStdEncoding
}

func trimBase64Padding(encoded string) string {
	return strings.TrimRight(strings.TrimSpace(encoded), "=")
}

func preparedAttachmentReader(decoder io.Reader, declared string) (string, io.Reader, error) {
	// Detecting the first bytes lets b64_json without a declared media type stay
	// previewable, without materializing a multi-megabyte attachment in memory.
	probe := make([]byte, 512)
	n, err := io.ReadFull(decoder, probe)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return "", nil, fmt.Errorf("read attachment probe: %w", err)
	}
	probe = probe[:n]
	contentType := strings.TrimSpace(strings.Split(declared, ";")[0])
	if contentType == "" || strings.Contains(contentType, "*") || contentType == "application/octet-stream" {
		contentType = strings.TrimSpace(strings.Split(http.DetectContentType(probe), ";")[0])
	}
	return contentType, io.MultiReader(bytes.NewReader(probe), decoder), nil
}

func isSafeAttachmentContentType(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	return mediaType != "" && !strings.Contains(mediaType, "*")
}

func attachmentFilename(manifest AttachmentManifest, contentType string) string {
	if filename := strings.TrimSpace(manifest.Filename); filename != "" {
		return filename
	}
	return manifest.ID + attachmentExtension(contentType)
}

func attachmentExtension(contentType string) string {
	switch strings.ToLower(strings.TrimSpace(contentType)) {
	case "image/png":
		return ".png"
	case "image/jpeg":
		return ".jpg"
	case "image/gif":
		return ".gif"
	case "image/webp":
		return ".webp"
	case "application/pdf":
		return ".pdf"
	default:
		return ".bin"
	}
}

func attachmentAttributes(manifest AttachmentManifest, reason string) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.String("gateway.attachment.id", manifest.ID),
		attribute.String("gateway.attachment.stage", manifest.Stage),
		attribute.String("gateway.attachment.role", string(manifest.Role)),
		attribute.String("gateway.attachment.kind", string(manifest.Kind)),
		attribute.String("gateway.attachment.mime_type", manifest.MIMEType),
		attribute.Int64("gateway.attachment.byte_size", manifest.ByteSize),
		attribute.String("gateway.attachment.source", string(manifest.Source)),
		attribute.String("gateway.attachment.storage_state", string(manifest.StorageState)),
	}
	if manifest.SHA256 != "" {
		attrs = append(attrs, attribute.String("gateway.attachment.sha256", manifest.SHA256))
	}
	if manifest.Filename != "" {
		attrs = append(attrs, attribute.String("gateway.attachment.filename", manifest.Filename))
	}
	if manifest.ViewerPath != "" {
		attrs = append(attrs, attribute.String("gateway.attachment.viewer_path", manifest.ViewerPath))
	}
	if reason != "" {
		attrs = append(attrs, attribute.String("gateway.attachment.reason", reason))
	}
	return attrs
}
