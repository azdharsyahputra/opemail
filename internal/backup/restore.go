package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type RestoreResult struct {
	FilesRestored int      `json:"files_restored"`
	TargetDir     string   `json:"target_dir"`
	Errors        []string `json:"errors,omitempty"`
}

// RestoreBackup unpacks archive contents into destination directory.
func RestoreBackup(ctx context.Context, archivePath, passphrase, targetDir string) (*RestoreResult, error) {
	report, err := VerifyBackup(archivePath, passphrase)
	if err != nil {
		return nil, fmt.Errorf("pre-restore verification failed: %w", err)
	}
	if !report.Valid {
		return nil, fmt.Errorf("archive validation errors: %v", report.Errors)
	}

	raw, err := os.ReadFile(archivePath)
	if err != nil {
		return nil, err
	}

	decrypted, err := DecryptData(raw, passphrase)
	if err != nil {
		return nil, err
	}

	gzReader, err := gzip.NewReader(bytes.NewReader(decrypted))
	if err != nil {
		return nil, err
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)
	result := &RestoreResult{TargetDir: targetDir}

	for {
		hdr, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		targetPath := filepath.Join(targetDir, hdr.Name)
		parentDir := filepath.Dir(targetPath)
		if err := os.MkdirAll(parentDir, 0750); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Mkdir %s: %v", parentDir, err))
			continue
		}

		content, err := io.ReadAll(tarReader)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Read %s: %v", hdr.Name, err))
			continue
		}

		mode := os.FileMode(hdr.Mode)
		if mode == 0 {
			mode = 0600
		}
		if err := os.WriteFile(targetPath, content, mode); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Write %s: %v", targetPath, err))
			continue
		}

		result.FilesRestored++
	}

	return result, nil
}
