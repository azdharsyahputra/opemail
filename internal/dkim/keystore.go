package dkim

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Keystore defines the filesystem storage for DKIM private keys.
type Keystore interface {
	StorePrivateKey(ctx context.Context, domain, selector string, privPEM []byte) (string, error)
	GetPrivateKey(ctx context.Context, domain, selector string) ([]byte, error)
	GetPrivateKeyPath(domain, selector string) string
	HasPrivateKey(domain, selector string) bool
	DeletePrivateKey(ctx context.Context, domain, selector string) error
}

type FilesystemKeystore struct {
	baseDir string
}

func NewFilesystemKeystore(baseDir string) *FilesystemKeystore {
	return &FilesystemKeystore{baseDir: baseDir}
}

func (k *FilesystemKeystore) GetPrivateKeyPath(domain, selector string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	selector = strings.ToLower(strings.TrimSpace(selector))
	return filepath.Join(k.baseDir, domain, selector, "private.key")
}

func (k *FilesystemKeystore) HasPrivateKey(domain, selector string) bool {
	p := k.GetPrivateKeyPath(domain, selector)
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

func (k *FilesystemKeystore) GetPrivateKey(ctx context.Context, domain, selector string) ([]byte, error) {
	if err := ValidateSelector(selector); err != nil {
		return nil, err
	}
	p := k.GetPrivateKeyPath(domain, selector)
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("read private key %s: %w", p, ErrPrivateKeyNotFound)
	}
	return data, nil
}

func (k *FilesystemKeystore) StorePrivateKey(ctx context.Context, domain, selector string, privPEM []byte) (string, error) {
	if err := ValidateSelector(selector); err != nil {
		return "", err
	}
	if len(privPEM) == 0 {
		return "", fmt.Errorf("empty private key data")
	}

	targetPath := k.GetPrivateKeyPath(domain, selector)
	dir := filepath.Dir(targetPath)

	if err := os.MkdirAll(dir, 0750); err != nil {
		return "", fmt.Errorf("create directory %s: %w", dir, err)
	}

	// Atomic write with 0600 permission
	tmpFile, err := os.CreateTemp(dir, "private.key.tmp-*")
	if err != nil {
		return "", fmt.Errorf("create temp key file: %w", err)
	}
	tmpName := tmpFile.Name()
	defer func() {
		_ = os.Remove(tmpName)
	}()

	if _, err := tmpFile.Write(privPEM); err != nil {
		_ = tmpFile.Close()
		return "", fmt.Errorf("write key bytes: %w", err)
	}

	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return "", fmt.Errorf("fsync key: %w", err)
	}

	if err := tmpFile.Chmod(0600); err != nil {
		_ = tmpFile.Close()
		return "", fmt.Errorf("chmod 0600 key: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		return "", fmt.Errorf("close temp key: %w", err)
	}

	if err := os.Rename(tmpName, targetPath); err != nil {
		return "", fmt.Errorf("rename key: %w", err)
	}

	return targetPath, nil
}

func (k *FilesystemKeystore) DeletePrivateKey(ctx context.Context, domain, selector string) error {
	if err := ValidateSelector(selector); err != nil {
		return err
	}
	targetPath := k.GetPrivateKeyPath(domain, selector)
	if err := os.Remove(targetPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("delete key %s: %w", targetPath, err)
	}
	// Try cleaning up the selector directory
	_ = os.Remove(filepath.Dir(targetPath))
	return nil
}
