package storage_test

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/azdharsyahputra/openmail/internal/storage"
)

func TestFilesystemBlobStore(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "openmail-blobs-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	store, err := storage.NewFilesystemBlobStore(tempDir)
	if err != nil {
		t.Fatalf("failed to init filesystem blob store: %v", err)
	}
	ctx := context.Background()

	rawEmail := "From: alice@example.com\r\nTo: ajar@example.com\r\nSubject: Test Email\r\n\r\nHello Ajar!"

	t.Run("Put valid payload", func(t *testing.T) {
		blob, err := store.Put(ctx, strings.NewReader(rawEmail))
		if err != nil {
			t.Fatalf("expected no error putting blob, got %v", err)
		}

		if blob.ID == "" {
			t.Error("expected non-empty blob ID")
		}
		if blob.SizeBytes != int64(len(rawEmail)) {
			t.Errorf("expected size %d, got %d", len(rawEmail), blob.SizeBytes)
		}

		// Verify sharded path on filesystem
		expectedPath := filepath.Join(tempDir, blob.ID[:2], blob.ID)
		if _, err := os.Stat(expectedPath); os.IsNotExist(err) {
			t.Errorf("expected file at %s to exist", expectedPath)
		}
	})

	t.Run("Put empty payload", func(t *testing.T) {
		_, err := store.Put(ctx, strings.NewReader(""))
		if err != storage.ErrEmptyPayload {
			t.Errorf("expected ErrEmptyPayload, got %v", err)
		}
	})

	t.Run("Get and verify payload content", func(t *testing.T) {
		blob, err := store.Put(ctx, strings.NewReader(rawEmail))
		if err != nil {
			t.Fatalf("failed to put blob: %v", err)
		}

		rc, err := store.Get(ctx, blob.ID)
		if err != nil {
			t.Fatalf("failed to get blob: %v", err)
		}
		defer rc.Close()

		buf := new(bytes.Buffer)
		_, err = io.Copy(buf, rc)
		if err != nil {
			t.Fatalf("failed to read blob: %v", err)
		}

		if buf.String() != rawEmail {
			t.Errorf("expected content %q, got %q", rawEmail, buf.String())
		}
	})

	t.Run("Get nonexistent blob", func(t *testing.T) {
		nonexistentID := strings.Repeat("a", 64)
		_, err := store.Get(ctx, nonexistentID)
		if err != storage.ErrBlobNotFound {
			t.Errorf("expected ErrBlobNotFound, got %v", err)
		}
	})

	t.Run("Exists check", func(t *testing.T) {
		blob, err := store.Put(ctx, strings.NewReader("some content"))
		if err != nil {
			t.Fatalf("failed to put blob: %v", err)
		}

		exists, err := store.Exists(ctx, blob.ID)
		if err != nil || !exists {
			t.Errorf("expected blob to exist, exists=%v, err=%v", exists, err)
		}

		nonexistentID := strings.Repeat("b", 64)
		exists, err = store.Exists(ctx, nonexistentID)
		if err != nil || exists {
			t.Errorf("expected nonexistent blob to return false, exists=%v, err=%v", exists, err)
		}
	})

	t.Run("Delete blob", func(t *testing.T) {
		blob, err := store.Put(ctx, strings.NewReader("to be deleted"))
		if err != nil {
			t.Fatalf("failed to put blob: %v", err)
		}

		err = store.Delete(ctx, blob.ID)
		if err != nil {
			t.Fatalf("failed to delete blob: %v", err)
		}

		_, err = store.Get(ctx, blob.ID)
		if err != storage.ErrBlobNotFound {
			t.Errorf("expected ErrBlobNotFound after delete, got %v", err)
		}
	})

	t.Run("Delete nonexistent blob", func(t *testing.T) {
		nonexistentID := strings.Repeat("c", 64)
		err := store.Delete(ctx, nonexistentID)
		if err != storage.ErrBlobNotFound {
			t.Errorf("expected ErrBlobNotFound, got %v", err)
		}
	})

	t.Run("Path traversal protection", func(t *testing.T) {
		invalidIDs := []string{"../etc/passwd", "7f/../../secret", "1", ""}
		for _, id := range invalidIDs {
			_, err := store.Get(ctx, id)
			if err != storage.ErrInvalidID {
				t.Errorf("expected ErrInvalidID for %q, got %v", id, err)
			}
		}
	})
}
