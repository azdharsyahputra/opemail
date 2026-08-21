package storage_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/azdharsyahputra/openmail/internal/storage"
)

type mockRefProvider struct {
	referenced map[string]bool
}

func (m *mockRefProvider) GetAllBlobIDs(ctx context.Context) (map[string]bool, error) {
	return m.referenced, nil
}

func TestGarbageCollect(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "openmail-gc-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	store, err := storage.NewFilesystemBlobStore(tempDir)
	if err != nil {
		t.Fatalf("failed to init store: %v", err)
	}
	ctx := context.Background()

	// 1. Create referenced blob
	blob1, err := store.Put(ctx, strings.NewReader("referenced blob payload"))
	if err != nil {
		t.Fatalf("failed to put blob1: %v", err)
	}

	// 2. Create orphan blob (not in referenced provider)
	blob2, err := store.Put(ctx, strings.NewReader("orphan blob payload"))
	if err != nil {
		t.Fatalf("failed to put blob2: %v", err)
	}

	refProvider := &mockRefProvider{
		referenced: map[string]bool{
			blob1.ID: true,
		},
	}

	// Dry run test
	stats, err := storage.GarbageCollect(ctx, store, refProvider, true)
	if err != nil {
		t.Fatalf("gc dry run failed: %v", err)
	}
	if stats.OrphanBlobs != 1 || stats.DeletedBlobs != 0 {
		t.Errorf("expected 1 orphan and 0 deleted in dry run, got %+v", stats)
	}

	// Active GC test
	stats, err = storage.GarbageCollect(ctx, store, refProvider, false)
	if err != nil {
		t.Fatalf("gc active run failed: %v", err)
	}
	if stats.OrphanBlobs != 1 || stats.DeletedBlobs != 1 {
		t.Errorf("expected 1 orphan and 1 deleted in active run, got %+v", stats)
	}

	// Verify blob1 exists and blob2 is removed
	exists, err := store.Exists(ctx, blob1.ID)
	if err != nil || !exists {
		t.Errorf("expected referenced blob to exist, exists=%v, err=%v", exists, err)
	}

	exists, err = store.Exists(ctx, blob2.ID)
	if err != nil || exists {
		t.Errorf("expected orphan blob to be deleted, exists=%v, err=%v", exists, err)
	}
}
