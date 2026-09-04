package observability

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"

	"go.opentelemetry.io/otel/trace"
)

const gatewayFileIDPrefix = "file_sub2api_"

var (
	ErrGatewayFileNotFound  = errors.New("gateway file not found")
	ErrGatewayFileForbidden = errors.New("gateway file is not available for this API key")
	ErrGatewayFileTooLarge  = errors.New("gateway file exceeds the configured size limit")
	ErrGatewayFileEmpty     = errors.New("gateway file is empty")
	gatewayFileIDPattern    = regexp.MustCompile(`^file_sub2api_[0-9a-f]{32}$`)
)

// GatewayFile is the safe subset of metadata returned by the local Files API.
// It never contains an object-store key or credentials.
type GatewayFile struct {
	ID       string
	Filename string
	MIMEType string
	ByteSize int64
	SHA256   string
}

// GatewayFileMaxBytes exposes the active upload bound without exposing the
// storage implementation. A zero result means the private store is disabled.
func GatewayFileMaxBytes() int64 {
	runtime := configuredAttachmentRuntime.Load()
	if runtime == nil {
		return 0
	}
	return runtime.cfg.MaxBytes
}

func IsGatewayFileID(id string) bool {
	return gatewayFileIDPattern.MatchString(strings.TrimSpace(id))
}

// RecordGatewayFile emits the metadata for a file that was synchronously
// stored through /v1/files. The bytes remain in private object storage; only
// the stable ID and safe metadata enter the trace.
func RecordGatewayFile(span trace.Span, stage PayloadStage, file GatewayFile) {
	if span == nil || !span.IsRecording() || !span.SpanContext().IsSampled() {
		return
	}
	manifest := AttachmentManifest{
		ID:           file.ID,
		Stage:        string(stage),
		Role:         attachmentRoleForStage(string(stage)),
		Kind:         AttachmentKindFile,
		MIMEType:     file.MIMEType,
		Filename:     file.Filename,
		ByteSize:     file.ByteSize,
		SHA256:       file.SHA256,
		Source:       AttachmentSourceGatewayFile,
		StorageState: AttachmentStorageStored,
		ViewerPath:   AttachmentViewerPath(file.ID),
	}
	span.AddEvent(attachmentEventName, trace.WithAttributes(attachmentAttributes(manifest, "")...))
}

// StoreGatewayFile persists a client-uploaded file before returning its ID.
// Uploads are intentionally synchronous: a returned file_id always refers to
// an object that can be resolved by a later Responses request. The request is
// bounded and spooled to a temporary file so neither memory nor object-store
// availability is part of the model forwarding path.
func StoreGatewayFile(ctx context.Context, ownerAPIKeyID int64, filename, declaredContentType string, body io.Reader) (GatewayFile, error) {
	runtime := configuredAttachmentRuntime.Load()
	if runtime == nil {
		return GatewayFile{}, ErrAttachmentStorageUnavailable
	}
	if ownerAPIKeyID <= 0 {
		return GatewayFile{}, ErrGatewayFileForbidden
	}
	if body == nil {
		return GatewayFile{}, ErrGatewayFileEmpty
	}

	temp, err := os.CreateTemp("", "sub2api-file-*")
	if err != nil {
		return GatewayFile{}, fmt.Errorf("create file spool: %w", err)
	}
	tempPath := temp.Name()
	defer func() {
		_ = temp.Close()
		_ = os.Remove(tempPath)
	}()

	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(temp, hash), io.LimitReader(body, runtime.cfg.MaxBytes+1))
	if err != nil {
		return GatewayFile{}, fmt.Errorf("spool uploaded file: %w", err)
	}
	if written == 0 {
		return GatewayFile{}, ErrGatewayFileEmpty
	}
	if written > runtime.cfg.MaxBytes {
		return GatewayFile{}, ErrGatewayFileTooLarge
	}
	if _, err := temp.Seek(0, io.SeekStart); err != nil {
		return GatewayFile{}, fmt.Errorf("rewind uploaded file: %w", err)
	}

	contentType := gatewayFileContentType(declaredContentType, filename, temp)
	if _, err := temp.Seek(0, io.SeekStart); err != nil {
		return GatewayFile{}, fmt.Errorf("rewind uploaded file: %w", err)
	}
	id, err := newGatewayFileID()
	if err != nil {
		return GatewayFile{}, err
	}
	storeCtx, cancel := context.WithTimeout(ctx, runtime.cfg.UploadTimeout)
	defer cancel()
	if err := runtime.storage.Put(storeCtx, AttachmentObject{
		Key:           runtime.gatewayFileObjectKey(id),
		ContentType:   contentType,
		Filename:      gatewayFileFilename(filename, id),
		Size:          written,
		OwnerAPIKeyID: ownerAPIKeyID,
	}, temp); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return GatewayFile{}, fmt.Errorf("store uploaded file: %w", context.DeadlineExceeded)
		}
		return GatewayFile{}, fmt.Errorf("store uploaded file: %w", err)
	}
	return GatewayFile{
		ID:       id,
		Filename: gatewayFileFilename(filename, id),
		MIMEType: contentType,
		ByteSize: written,
		SHA256:   hex.EncodeToString(hash.Sum(nil)),
	}, nil
}

// ResolveGatewayFileReferences replaces only locally-issued input_file IDs
// with standard file_data values. Provider file IDs are deliberately ignored
// and left unchanged; Sub2API never attempts to fetch them.
func ResolveGatewayFileReferences(ctx context.Context, ownerAPIKeyID int64, raw []byte) ([]byte, bool, error) {
	if len(raw) == 0 || !bytes.Contains(raw, []byte(gatewayFileIDPrefix)) {
		return raw, false, nil
	}
	var value any
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, false, fmt.Errorf("decode local file references: %w", err)
	}
	changed, err := resolveGatewayFileValue(ctx, ownerAPIKeyID, value)
	if err != nil || !changed {
		return raw, changed, err
	}
	resolved, err := json.Marshal(value)
	if err != nil {
		return nil, false, fmt.Errorf("encode resolved local file references: %w", err)
	}
	return resolved, true, nil
}

func resolveGatewayFileValue(ctx context.Context, ownerAPIKeyID int64, value any) (bool, error) {
	switch typed := value.(type) {
	case map[string]any:
		changed := false
		if strings.EqualFold(stringValue(typed["type"]), "input_file") {
			if id := strings.TrimSpace(stringValue(typed["file_id"])); IsGatewayFileID(id) {
				data, info, err := openGatewayFileBytes(ctx, ownerAPIKeyID, id)
				if err != nil {
					return false, err
				}
				typed["file_data"] = "data:" + info.ContentType + ";base64," + base64.StdEncoding.EncodeToString(data)
				delete(typed, "file_id")
				if strings.TrimSpace(stringValue(typed["filename"])) == "" {
					typed["filename"] = info.Filename
				}
				changed = true
			}
		}
		for _, item := range typed {
			childChanged, err := resolveGatewayFileValue(ctx, ownerAPIKeyID, item)
			if err != nil {
				return false, err
			}
			changed = changed || childChanged
		}
		return changed, nil
	case []any:
		changed := false
		for _, item := range typed {
			childChanged, err := resolveGatewayFileValue(ctx, ownerAPIKeyID, item)
			if err != nil {
				return false, err
			}
			changed = changed || childChanged
		}
		return changed, nil
	default:
		return false, nil
	}
}

func openGatewayFileBytes(ctx context.Context, ownerAPIKeyID int64, id string) ([]byte, AttachmentObjectInfo, error) {
	runtime := configuredAttachmentRuntime.Load()
	if runtime == nil {
		return nil, AttachmentObjectInfo{}, ErrAttachmentStorageUnavailable
	}
	if ownerAPIKeyID <= 0 || !IsGatewayFileID(id) {
		return nil, AttachmentObjectInfo{}, ErrGatewayFileForbidden
	}
	readCtx, cancel := context.WithTimeout(ctx, runtime.cfg.UploadTimeout)
	defer cancel()
	stream, info, err := runtime.storage.Get(readCtx, runtime.gatewayFileObjectKey(id))
	if err != nil {
		if errors.Is(err, ErrAttachmentNotFound) {
			return nil, AttachmentObjectInfo{}, ErrGatewayFileNotFound
		}
		return nil, AttachmentObjectInfo{}, err
	}
	defer stream.Close()
	if info.OwnerAPIKeyID != ownerAPIKeyID {
		return nil, AttachmentObjectInfo{}, ErrGatewayFileForbidden
	}
	if info.Size <= 0 {
		return nil, AttachmentObjectInfo{}, ErrGatewayFileNotFound
	}
	if info.Size > runtime.cfg.MaxBytes {
		return nil, AttachmentObjectInfo{}, ErrGatewayFileTooLarge
	}
	data, err := io.ReadAll(io.LimitReader(stream, runtime.cfg.MaxBytes+1))
	if err != nil {
		return nil, AttachmentObjectInfo{}, fmt.Errorf("read local file: %w", err)
	}
	if int64(len(data)) != info.Size {
		return nil, AttachmentObjectInfo{}, ErrGatewayFileNotFound
	}
	return data, info, nil
}

func (r *AttachmentRuntime) gatewayFileObjectKey(id string) string {
	return r.cfg.ObjectKeyPrefix + "files/" + id
}

func newGatewayFileID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate local file ID: %w", err)
	}
	return gatewayFileIDPrefix + hex.EncodeToString(bytes), nil
}

func gatewayFileContentType(declared, filename string, file *os.File) string {
	if mediaType, _, err := mime.ParseMediaType(strings.TrimSpace(declared)); err == nil && mediaType != "" && !strings.Contains(mediaType, "*") {
		return mediaType
	}
	if byExtension := mime.TypeByExtension(strings.ToLower(filepath.Ext(filename))); byExtension != "" {
		if mediaType, _, err := mime.ParseMediaType(byExtension); err == nil && mediaType != "" {
			return mediaType
		}
	}
	probe := make([]byte, 512)
	n, _ := io.ReadFull(file, probe)
	if n > 0 {
		return strings.TrimSpace(strings.Split(http.DetectContentType(probe[:n]), ";")[0])
	}
	return "application/octet-stream"
}

func gatewayFileFilename(value, id string) string {
	name := strings.TrimSpace(filepath.Base(strings.ReplaceAll(value, `\`, "/")))
	if name == "" || name == "." || name == string(filepath.Separator) {
		return id + ".bin"
	}
	name = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, name)
	if name == "" {
		return id + ".bin"
	}
	return name
}

func stringValue(value any) string {
	stringValue, _ := value.(string)
	return stringValue
}
