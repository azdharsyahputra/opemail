package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/google/uuid"
)

var idRegex = regexp.MustCompile(`^[a-f0-9]{32,64}$`)

type FilesystemBlobStore struct {
	baseDir string
	tmpDir  string
}

// NewFilesystemBlobStore creates a new filesystem-backed BlobStore.
func NewFilesystemBlobStore(baseDir string) (*FilesystemBlobStore, error) {
	if baseDir == "" {
		return nil, errors.New("base directory cannot be empty")
	}

	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		return nil, fmt.Errorf("invalid base directory: %w", err)
	}

	tmpDir := filepath.Join(absBase, "tmp")
	if err := os.MkdirAll(tmpDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create storage directories: %w", err)
	}

	return &FilesystemBlobStore{
		baseDir: absBase,
		tmpDir:  tmpDir,
	}, nil
}

// Put streams data from r to a temporary file, computes its SHA-256, and moves it to its sharded location.
func (s *FilesystemBlobStore) Put(ctx context.Context, r io.Reader) (Blob, error) {
	if r == nil {
		return Blob{}, ErrEmptyPayload
	}

	// 1. Write to temporary file while calculating SHA256 hash and counting bytes
	tempFile, err := os.CreateTemp(s.tmpDir, "upload-*")
	if err != nil {
		return Blob{}, fmt.Errorf("failed to create temporary file: %w", err)
	}
	tempPath := tempFile.Name()
	defer func() {
		// Clean up temp file if it still exists
		if _, err := os.Stat(tempPath); err == nil {
			_ = os.Remove(tempPath)
		}
	}()

	hasher := sha256.New()
	multiWriter := io.MultiWriter(tempFile, hasher)

	written, err := io.Copy(multiWriter, r)
	if closeErr := tempFile.Close(); closeErr != nil && err == nil {
		err = closeErr
	}
	if err != nil {
		return Blob{}, fmt.Errorf("failed to write payload: %w", err)
	}

	if written == 0 {
		return Blob{}, ErrEmptyPayload
	}

	hashStr := hex.EncodeToString(hasher.Sum(nil))
	blobID := hashStr

	// 2. Prepare sharded destination directory: <baseDir>/<prefix2>/<id>
	prefix := blobID[:2]
	destDir := filepath.Join(s.baseDir, prefix)
	if err := os.MkdirAll(destDir, 0750); err != nil {
		return Blob{}, fmt.Errorf("failed to create sharded directory: %w", err)
	}

	destPath := filepath.Join(destDir, blobID)

	// 3. Atomically move/rename temporary file to destination
	if err := os.Rename(tempPath, destPath); err != nil {
		// If destination already exists (due to content-addressable deduplication), it's safe to overwrite or remove temp
		if _, statErr := os.Stat(destPath); statErr == nil {
			_ = os.Remove(tempPath)
		} else {
			return Blob{}, fmt.Errorf("failed to store blob: %w", err)
		}
	}

	return Blob{
		ID:        blobID,
		SizeBytes: written,
		SHA256:    hashStr,
		CreatedAt: time.Now().UTC(),
	}, nil
}

// Get opens a ReadCloser for the requested blob ID.
func (s *FilesystemBlobStore) Get(ctx context.Context, id string) (io.ReadCloser, error) {
	blobPath, err := s.resolveBlobPath(id)
	if err != nil {
		return nil, err
	}

	file, err := os.Open(blobPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrBlobNotFound
		}
		return nil, fmt.Errorf("failed to read blob: %w", err)
	}

	return file, nil
}

// Delete removes the specified blob from the filesystem.
func (s *FilesystemBlobStore) Delete(ctx context.Context, id string) error {
	blobPath, err := s.resolveBlobPath(id)
	if err != nil {
		return err
	}

	err = os.Remove(blobPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrBlobNotFound
		}
		return fmt.Errorf("failed to delete blob: %w", err)
	}

	return nil
}

// Exists checks if the blob exists in the filesystem.
func (s *FilesystemBlobStore) Exists(ctx context.Context, id string) (bool, error) {
	blobPath, err := s.resolveBlobPath(id)
	if err != nil {
		return false, err
	}

	_, err = os.Stat(blobPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

func (s *FilesystemBlobStore) resolveBlobPath(id string) (string, error) {
	if len(id) < 2 || !idRegex.MatchString(id) {
		return "", ErrInvalidID
	}

	prefix := id[:2]
	targetPath := filepath.Join(s.baseDir, prefix, id)

	// Ensure path stays within baseDir
	rel, err := filepath.Rel(s.baseDir, targetPath)
	if err != nil || len(rel) > 0 && rel[0] == '.' {
		return "", ErrInvalidID
	}

	return targetPath, nil
}

// NewUUID generates a random hex identifier if needed for alternative ID schemas.
func NewUUID() string {
	return hex.EncodeToString([]byte(uuid.New().String()))
}
