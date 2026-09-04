package handler

import (
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/observability"
	middleware2 "github.com/Wei-Shaw/sub2api/internal/server/middleware"

	"github.com/gin-gonic/gin"
)

const gatewayFileMultipartOverheadMaxBytes int64 = 1 << 20

// UploadGatewayFile implements the local, OpenAI-compatible POST /v1/files
// contract. The response is sent only after the private object store confirms
// persistence, so callers never receive an unusable local file_id.
func UploadGatewayFile(c *gin.Context) {
	traceCtx, requestSpan := observability.StartGatewayRequest(c.Request.Context(), c.Request.URL.Path)
	c.Request = c.Request.WithContext(traceCtx)
	responseWriter := observability.NewResponseWriter(c.Writer, requestSpan)
	c.Writer = responseWriter
	defer func() {
		responseWriter.Finalize()
		observability.EndGatewayRequest(requestSpan, c.Writer.Status())
	}()

	apiKey, ok := middleware2.GetAPIKeyFromContext(c)
	if !ok || apiKey == nil {
		writeGatewayFileError(c, http.StatusUnauthorized, "authentication_error", "Invalid API key")
		return
	}
	maxBytes := observability.GatewayFileMaxBytes()
	if maxBytes <= 0 {
		writeGatewayFileError(c, http.StatusServiceUnavailable, "server_error", "Local file storage is unavailable")
		return
	}
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(c.GetHeader("Content-Type"))), "multipart/form-data") {
		writeGatewayFileError(c, http.StatusBadRequest, "invalid_request_error", "Content-Type must be multipart/form-data")
		return
	}

	// The gateway-wide limit is intentionally larger. Apply a smaller endpoint
	// limit before MultipartReader so arbitrary form fields cannot bypass the
	// configured per-file bound.
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes+gatewayFileMultipartOverheadMaxBytes)
	reader, err := c.Request.MultipartReader()
	if err != nil {
		writeGatewayFileError(c, http.StatusBadRequest, "invalid_request_error", "Invalid multipart upload")
		return
	}
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			writeGatewayFileError(c, http.StatusBadRequest, "invalid_request_error", "Invalid multipart upload")
			return
		}
		if part.FormName() != "file" || part.FileName() == "" {
			_, _ = io.Copy(io.Discard, io.LimitReader(part, gatewayFileMultipartOverheadMaxBytes))
			_ = part.Close()
			continue
		}

		file, storeErr := observability.StoreGatewayFile(
			c.Request.Context(),
			apiKey.ID,
			part.FileName(),
			part.Header.Get("Content-Type"),
			part,
		)
		_ = part.Close()
		if storeErr != nil {
			writeGatewayFileStoreError(c, storeErr)
			return
		}
		observability.RecordGatewayFile(requestSpan, observability.PayloadStageClientRequest, file)
		c.JSON(http.StatusOK, gin.H{
			"id":       file.ID,
			"object":   "file",
			"bytes":    file.ByteSize,
			"filename": file.Filename,
			"sha256":   file.SHA256,
			"purpose":  "user_data",
			"status":   "processed",
		})
		return
	}
	writeGatewayFileError(c, http.StatusBadRequest, "invalid_request_error", "Multipart field 'file' is required")
}

func resolveGatewayFilesForRequest(c *gin.Context, ownerAPIKeyID int64, body []byte) ([]byte, error) {
	resolved, _, err := observability.ResolveGatewayFileReferences(c.Request.Context(), ownerAPIKeyID, body)
	return resolved, err
}

func gatewayFileResolutionError(err error) (int, string) {
	switch {
	case errors.Is(err, observability.ErrAttachmentStorageUnavailable):
		return http.StatusServiceUnavailable, "Local file storage is unavailable"
	case errors.Is(err, observability.ErrGatewayFileNotFound), errors.Is(err, observability.ErrGatewayFileForbidden):
		return http.StatusBadRequest, "input_file.file_id is not available for this API key"
	case errors.Is(err, observability.ErrGatewayFileTooLarge):
		return http.StatusBadRequest, "input_file.file_id exceeds the configured size limit"
	default:
		return http.StatusBadGateway, "Failed to resolve local file_id"
	}
}

func writeGatewayFileStoreError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, observability.ErrAttachmentStorageUnavailable):
		writeGatewayFileError(c, http.StatusServiceUnavailable, "server_error", "Local file storage is unavailable")
	case errors.Is(err, observability.ErrGatewayFileTooLarge):
		writeGatewayFileError(c, http.StatusRequestEntityTooLarge, "invalid_request_error", "Uploaded file exceeds the configured size limit")
	case errors.Is(err, observability.ErrGatewayFileEmpty):
		writeGatewayFileError(c, http.StatusBadRequest, "invalid_request_error", "Uploaded file is empty")
	default:
		writeGatewayFileError(c, http.StatusBadGateway, "server_error", "Failed to store uploaded file")
	}
}

func writeGatewayFileError(c *gin.Context, status int, errType, message string) {
	c.JSON(status, gin.H{
		"error": gin.H{
			"type":    errType,
			"message": message,
		},
	})
}
