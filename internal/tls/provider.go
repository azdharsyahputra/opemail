package tls

import "context"

// CertificateProvider defines operations for loading, validating, and installing TLS certificates.
type CertificateProvider interface {
	Load(ctx context.Context, hostname string) (*Certificate, error)
	Validate(ctx context.Context, hostname string) (*CertificateReport, error)
	Install(ctx context.Context, hostname string, certPEM, keyPEM []byte) (*CertificateReport, error)
	GetPaths(hostname string) (certPath, keyPath string)
}
