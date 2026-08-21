package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// VerifyBackup checks decryptability, tar/gzip integrity, manifest validity, and sha256 checksums of every file.
func VerifyBackup(archivePath, passphrase string) (*VerificationReport, error) {
	raw, err := os.ReadFile(archivePath)
	if err != nil {
		return nil, fmt.Errorf("read archive: %w", err)
	}

	report := &VerificationReport{Valid: true}

	// 1. Decrypt if needed
	decrypted, err := DecryptData(raw, passphrase)
	if err != nil {
		report.Valid = false
		report.Errors = append(report.Errors, fmt.Sprintf("Decryption failed: %v", err))
		return report, nil
	}

	// 2. Gzip Reader
	gzReader, err := gzip.NewReader(bytes.NewReader(decrypted))
	if err != nil {
		report.Valid = false
		report.Errors = append(report.Errors, fmt.Sprintf("Gzip decompression failed: %v", err))
		return report, nil
	}
	defer gzReader.Close()

	// 3. Tar Reader
	tarReader := tar.NewReader(gzReader)
	var manifest Manifest
	var foundManifest bool
	extractedFiles := make(map[string][]byte)

	for {
		hdr, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			report.Valid = false
			report.Errors = append(report.Errors, fmt.Sprintf("Tar entry error: %v", err))
			return report, nil
		}

		content, err := io.ReadAll(tarReader)
		if err != nil {
			report.Valid = false
			report.Errors = append(report.Errors, fmt.Sprintf("Failed to read %s: %v", hdr.Name, err))
			continue
		}

		extractedFiles[hdr.Name] = content
		report.FileCount++

		if hdr.Name == "manifest.json" {
			if err := json.Unmarshal(content, &manifest); err == nil {
				foundManifest = true
				report.Manifest = manifest
			}
		}
	}

	if !foundManifest {
		report.Valid = false
		report.Errors = append(report.Errors, "Archive is missing manifest.json")
		return report, nil
	}

	// 4. Verify SHA-256 Checksums
	for name, expectedHash := range manifest.Checksums {
		if name == "manifest.json" {
			continue
		}
		content, ok := extractedFiles[name]
		if !ok {
			report.Valid = false
			report.Errors = append(report.Errors, fmt.Sprintf("Missing expected file %s from archive", name))
			continue
		}
		hasher := sha256.New()
		hasher.Write(content)
		actualHash := hex.EncodeToString(hasher.Sum(nil))
		if actualHash != expectedHash {
			report.Valid = false
			report.Errors = append(report.Errors, fmt.Sprintf("Checksum mismatch for %s (expected %s, got %s)", name, expectedHash, actualHash))
		}
	}

	return report, nil
}
