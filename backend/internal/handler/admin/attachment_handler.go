package admin

import (
	"errors"
	"mime"
	"net/http"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/Wei-Shaw/sub2api/internal/observability"
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/gin-gonic/gin"
)

// AttachmentHandler exposes a controlled, administrator-authenticated viewer
// for observability attachments. Authentication and audit logging are applied
// by the surrounding /api/v1/admin route group.
type AttachmentHandler struct{}

func NewAttachmentHandler() *AttachmentHandler { return &AttachmentHandler{} }

func (h *AttachmentHandler) Preview(c *gin.Context) {
	h.serve(c, false)
}

func (h *AttachmentHandler) Download(c *gin.Context) {
	h.serve(c, true)
}

func (h *AttachmentHandler) serve(c *gin.Context, forceDownload bool) {
	stream, info, err := observability.OpenAttachment(c.Request.Context(), c.Param("id"))
	if err != nil {
		switch {
		case errors.Is(err, observability.ErrAttachmentNotFound):
			response.NotFound(c, "attachment not found")
		case errors.Is(err, observability.ErrAttachmentStorageUnavailable):
			response.Error(c, http.StatusServiceUnavailable, "attachment storage is unavailable")
		default:
			response.Error(c, http.StatusBadGateway, "attachment storage read failed")
		}
		return
	}
	defer func() { _ = stream.Close() }()

	contentType := safeContentType(info.ContentType)
	filename := safeAttachmentFilename(info.Filename, c.Param("id"))
	disposition := "inline"
	if forceDownload || !previewableContentType(contentType) {
		disposition = "attachment"
	}
	c.Header("Content-Disposition", mime.FormatMediaType(disposition, map[string]string{"filename": filename}))
	c.Header("X-Content-Type-Options", "nosniff")
	c.DataFromReader(http.StatusOK, info.Size, contentType, stream, nil)
}

func safeContentType(value string) string {
	mediaType, _, err := mime.ParseMediaType(strings.TrimSpace(value))
	if err != nil || mediaType == "" || strings.Contains(mediaType, "*") {
		return "application/octet-stream"
	}
	return mediaType
}

func previewableContentType(contentType string) bool {
	return strings.HasPrefix(contentType, "image/") || contentType == "application/pdf" || contentType == "text/plain"
}

func safeAttachmentFilename(value, fallback string) string {
	value = strings.TrimSpace(filepath.Base(value))
	if value == "." || value == string(filepath.Separator) || value == "" {
		value = strings.TrimSpace(fallback) + ".bin"
	}
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == '/' || r == '\\' {
			return -1
		}
		return r
	}, value)
	if value == "" {
		return "attachment.bin"
	}
	return value
}
