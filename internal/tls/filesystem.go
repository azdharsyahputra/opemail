package tls

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

type FilesystemProvider struct {
	baseDir string
}

func NewFilesystemProvider(baseDir string) *FilesystemProvider {
	return &FilesystemProvider{baseDir: baseDir}
}

func (p *FilesystemProvider) GetPaths(hostname string) (certPath, keyPath string) {
	hostDir := filepath.Join(p.baseDir, hostname)
	return filepath.Join(hostDir, "fullchain.pem"), filepath.Join(hostDir, "privkey.pem")
}

func (p *FilesystemProvider) Load(ctx context.Context, hostname string) (*Certificate, error) {
	certPath, keyPath := p.GetPaths(hostname)

	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read cert %s: %w", certPath, ErrCertificateNotFound)
	}

	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read key %s: %w", keyPath, ErrCertificateNotFound)
	}

	_, certModel, err := ValidateBytes(certBytes, keyBytes, hostname)
	if err != nil {
		return nil, err
	}

	certModel.CertFile = certPath
	certModel.KeyFile = keyPath
	return certModel, nil
}

func (p *FilesystemProvider) Validate(ctx context.Context, hostname string) (*CertificateReport, error) {
	certPath, keyPath := p.GetPaths(hostname)

	report := &CertificateReport{
		Hostname: hostname,
	}

	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		report.Exists = false
		report.Message = fmt.Sprintf("Certificate file %s not found", certPath)
		return report, ErrCertificateNotFound
	}

	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		report.Exists = false
		report.Message = fmt.Sprintf("Private key file %s not found", keyPath)
		return report, ErrCertificateNotFound
	}

	rep, _, err := ValidateBytes(certBytes, keyBytes, hostname)
	return rep, err
}

func (p *FilesystemProvider) Install(ctx context.Context, hostname string, certPEM, keyPEM []byte) (*CertificateReport, error) {
	// 1. Strict Validation BEFORE modifying filesystem
	report, _, err := ValidateBytes(certPEM, keyPEM, hostname)
	if err != nil {
		return report, fmt.Errorf("certificate validation failed: %w", err)
	}

	hostDir := filepath.Join(p.baseDir, hostname)
	if err := os.MkdirAll(hostDir, 0750); err != nil {
		return report, fmt.Errorf("create tls directory %s: %w", hostDir, err)
	}

	certPath, keyPath := p.GetPaths(hostname)

	// 2. Atomic write private key with 0600
	if err := atomicWriteSecret(keyPath, keyPEM, 0600); err != nil {
		return report, fmt.Errorf("write private key: %w", err)
	}

	// 3. Atomic write fullchain certificate with 0644
	if err := atomicWriteSecret(certPath, certPEM, 0644); err != nil {
		return report, fmt.Errorf("write certificate chain: %w", err)
	}

	return report, nil
}

func atomicWriteSecret(targetPath string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(targetPath)
	tmpFile, err := os.CreateTemp(dir, filepath.Base(targetPath)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmpFile.Name()
	defer func() {
		_ = os.Remove(tmpName)
	}()

	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		return err
	}

	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return err
	}

	if err := tmpFile.Chmod(perm); err != nil {
		_ = tmpFile.Close()
		return err
	}

	if err := tmpFile.Close(); err != nil {
		return err
	}

	return os.Rename(tmpName, targetPath)
}
