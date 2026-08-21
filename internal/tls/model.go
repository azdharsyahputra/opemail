package tls

import (
	"errors"
	"time"
)

var (
	ErrCertificateNotFound = errors.New("certificate files not found")
	ErrInvalidPEM          = errors.New("invalid PEM certificate data")
	ErrInvalidPrivateKey   = errors.New("invalid private key data")
	ErrKeyMismatch         = errors.New("certificate public key does not match private key")
	ErrHostnameMismatch    = errors.New("hostname does not match certificate SAN / Common Name")
	ErrCertificateExpired  = errors.New("certificate has expired or is not yet valid")
)

type ExpirationStatus string

const (
	StatusHealthy  ExpirationStatus = "HEALTHY"  // > 30 days
	StatusWarning  ExpirationStatus = "WARNING"  // 8 - 30 days
	StatusCritical ExpirationStatus = "CRITICAL" // 1 - 7 days
	StatusExpired  ExpirationStatus = "EXPIRED"  // <= 0 days
)

type Certificate struct {
	Hostname    string    `json:"hostname"`
	CertFile    string    `json:"cert_file"`
	KeyFile     string    `json:"key_file"`
	Issuer      string    `json:"issuer"`
	Subject     string    `json:"subject"`
	DNSNames    []string  `json:"dns_names"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	Fingerprint string    `json:"fingerprint"`
}

type CertificateReport struct {
	Hostname        string           `json:"hostname"`
	Exists          bool             `json:"exists"`
	CertificateOK   bool             `json:"certificate_ok"`
	PrivateKeyOK    bool             `json:"private_key_ok"`
	KeyMatches      bool             `json:"key_matches"`
	HostnameMatches bool             `json:"hostname_matches"`
	Expired         bool             `json:"expired"`
	DaysRemaining   int              `json:"days_remaining"`
	Status          ExpirationStatus `json:"status"`
	Issuer          string           `json:"issuer,omitempty"`
	NotAfter        time.Time        `json:"not_after,omitempty"`
	Message         string           `json:"message,omitempty"`
}

func CalculateExpirationStatus(daysRemaining int, expired bool) ExpirationStatus {
	if expired || daysRemaining <= 0 {
		return StatusExpired
	}
	if daysRemaining <= 7 {
		return StatusCritical
	}
	if daysRemaining <= 30 {
		return StatusWarning
	}
	return StatusHealthy
}
