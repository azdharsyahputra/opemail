package storage

import (
	"context"
	"fmt"
)

type GCStats struct {
	TotalBlobs      int
	ReferencedBlobs int
	OrphanBlobs     int
	DeletedBlobs    int
}

type BlobReferenceProvider interface {
	GetAllBlobIDs(ctx context.Context) (map[string]bool, error)
}

// GarbageCollect compares blobs in BlobStore against active DB references and cleans up orphan blobs.
func GarbageCollect(ctx context.Context, store BlobStore, refProvider BlobReferenceProvider, dryRun bool) (*GCStats, error) {
	referenced, err := refProvider.GetAllBlobIDs(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve referenced blob ids from database: %w", err)
	}

	allBlobIDs, err := store.ListIDs(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list blob ids in storage: %w", err)
	}

	stats := &GCStats{
		TotalBlobs:      len(allBlobIDs),
		ReferencedBlobs: len(referenced),
	}

	for _, id := range allBlobIDs {
		if !referenced[id] {
			stats.OrphanBlobs++
			if !dryRun {
				if err := store.Delete(ctx, id); err == nil {
					stats.DeletedBlobs++
				}
			}
		}
	}

	return stats, nil
}
