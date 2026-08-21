package tls

import (
	"context"
	"fmt"
	"os"
)

type Service struct {
	provider CertificateProvider
}

func NewService(provider CertificateProvider) *Service {
	return &Service{provider: provider}
}

func (s *Service) Provider() CertificateProvider {
	return s.provider
}

func (s *Service) GetPaths(hostname string) (certPath, keyPath string) {
	return s.provider.GetPaths(hostname)
}

func (s *Service) Load(ctx context.Context, hostname string) (*Certificate, error) {
	return s.provider.Load(ctx, hostname)
}

func (s *Service) Validate(ctx context.Context, hostname string) (*CertificateReport, error) {
	return s.provider.Validate(ctx, hostname)
}

func (s *Service) Install(ctx context.Context, hostname, certFilePath, keyFilePath string) (*CertificateReport, error) {
	certPEM, err := os.ReadFile(certFilePath)
	if err != nil {
		return nil, fmt.Errorf("read cert file %s: %w", certFilePath, err)
	}

	keyPEM, err := os.ReadFile(keyFilePath)
	if err != nil {
		return nil, fmt.Errorf("read key file %s: %w", keyFilePath, err)
	}

	return s.provider.Install(ctx, hostname, certPEM, keyPEM)
}
