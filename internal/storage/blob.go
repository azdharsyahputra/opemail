package storage

import (
	"context"
	"io"
	"time"
)

// Blob represents metadata of a stored object in BlobStore.
type Blob struct {
	ID        string    `json:"id"`
	SizeBytes int64     `json:"size_bytes"`
	SHA256    string    `json:"sha256,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// BlobStore is the storage abstraction interface for raw email payloads and objects.
type BlobStore interface {
	Put(ctx context.Context, r io.Reader) (Blob, error)
	Get(ctx context.Context, id string) (io.ReadCloser, error)
	Delete(ctx context.Context, id string) error
	Exists(ctx context.Context, id string) (bool, error)
	ListIDs(ctx context.Context) ([]string, error)
}
