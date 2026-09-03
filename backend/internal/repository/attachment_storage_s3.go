package repository

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/observability"
	"github.com/Wei-Shaw/sub2api/internal/pkg/servertiming"
)

// S3AttachmentStorage is a private, S3-compatible attachment store. It
// intentionally implements controlled Get instead of returning public or
// presigned URLs; browser access remains behind Sub2API administrator auth.
type S3AttachmentStorage struct {
	client *s3.Client
	bucket string
}

var _ observability.AttachmentStorage = (*S3AttachmentStorage)(nil)

func NewS3AttachmentStorage(ctx context.Context, cfg config.ObservabilityAttachmentStorageConfig) (*S3AttachmentStorage, error) {
	if !cfg.IsConfigured() {
		return nil, errors.New("observability attachment storage is not fully configured")
	}
	client, err := newS3Client(ctx, s3ClientParams{
		Endpoint:        cfg.Endpoint,
		Region:          cfg.Region,
		AccessKeyID:     cfg.AccessKeyID,
		SecretAccessKey: cfg.SecretAccessKey,
		ForcePathStyle:  cfg.ForcePathStyle,
	})
	if err != nil {
		return nil, err
	}
	return &S3AttachmentStorage{client: client, bucket: cfg.Bucket}, nil
}

func (s *S3AttachmentStorage) Put(ctx context.Context, object observability.AttachmentObject, body io.Reader) error {
	if object.Size < 0 {
		return errors.New("attachment size is unknown")
	}
	metadata := map[string]string{}
	if filename := strings.TrimSpace(object.Filename); filename != "" {
		metadata["filename"] = filename
	}
	finish := servertiming.ObserveDependency(ctx, "s3")
	_, err := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        &s.bucket,
		Key:           &object.Key,
		Body:          body,
		ContentLength: &object.Size,
		ContentType:   &object.ContentType,
		Metadata:      metadata,
	})
	finish()
	if err != nil {
		return fmt.Errorf("S3 PutObject: %w", err)
	}
	return nil
}

func (s *S3AttachmentStorage) Head(ctx context.Context, key string) (observability.AttachmentObjectInfo, error) {
	finish := servertiming.ObserveDependency(ctx, "s3")
	result, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &s.bucket, Key: &key})
	finish()
	if err != nil {
		if s3ObjectNotFound(err) {
			return observability.AttachmentObjectInfo{}, observability.ErrAttachmentNotFound
		}
		return observability.AttachmentObjectInfo{}, fmt.Errorf("S3 HeadObject: %w", err)
	}
	return attachmentObjectInfo(result.ContentType, result.ContentLength, result.Metadata), nil
}

func (s *S3AttachmentStorage) Get(ctx context.Context, key string) (io.ReadCloser, observability.AttachmentObjectInfo, error) {
	finish := servertiming.ObserveDependency(ctx, "s3")
	result, err := s.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &s.bucket, Key: &key})
	finish()
	if err != nil {
		if s3ObjectNotFound(err) {
			return nil, observability.AttachmentObjectInfo{}, observability.ErrAttachmentNotFound
		}
		return nil, observability.AttachmentObjectInfo{}, fmt.Errorf("S3 GetObject: %w", err)
	}
	return result.Body, attachmentObjectInfo(result.ContentType, result.ContentLength, result.Metadata), nil
}

func attachmentObjectInfo(contentType *string, size *int64, metadata map[string]string) observability.AttachmentObjectInfo {
	info := observability.AttachmentObjectInfo{ContentType: "application/octet-stream"}
	if contentType != nil && strings.TrimSpace(*contentType) != "" {
		info.ContentType = *contentType
	}
	if size != nil {
		info.Size = *size
	}
	if metadata != nil {
		info.Filename = metadata["filename"]
	}
	return info
}

func s3ObjectNotFound(err error) bool {
	var apiErr interface{ ErrorCode() string }
	if errors.As(err, &apiErr) {
		switch strings.ToLower(strings.TrimSpace(apiErr.ErrorCode())) {
		case "nosuchkey", "notfound", "no such key":
			return true
		}
	}
	var statusErr interface{ HTTPStatusCode() int }
	return errors.As(err, &statusErr) && statusErr.HTTPStatusCode() == 404
}
