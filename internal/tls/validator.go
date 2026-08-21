package tls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"reflect"
	"strings"
	"time"
)

// ParseCertificates parses one or more PEM encoded certificates (certificate chain).
func ParseCertificates(certPEM []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := certPEM

	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse x509 certificate: %w", err)
		}
		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, ErrInvalidPEM
	}

	return certs, nil
}

// ParsePrivateKey parses a PEM encoded private key in PKCS#1, PKCS#8, or SEC1 EC format.
func ParsePrivateKey(keyPEM []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, ErrInvalidPrivateKey
	}

	// 1. Try PKCS#8 (standard across RSA, ECDSA, Ed25519)
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	// 2. Try PKCS#1 (RSA)
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	// 3. Try SEC1 (EC)
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	return nil, ErrInvalidPrivateKey
}

// PublicKeyMatches returns true if the public key in the certificate matches the public key of the private key.
func PublicKeyMatches(cert *x509.Certificate, privKey crypto.PrivateKey) bool {
	switch k := privKey.(type) {
	case *rsa.PrivateKey:
		certPub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return false
		}
		return k.PublicKey.Equal(certPub)
	case *ecdsa.PrivateKey:
		certPub, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return false
		}
		return k.PublicKey.Equal(certPub)
	case ed25519.PrivateKey:
		certPub, ok := cert.PublicKey.(ed25519.PublicKey)
		if !ok {
			return false
		}
		return reflect.DeepEqual(k.Public().(ed25519.PublicKey), certPub)
	case crypto.Signer:
		return reflect.DeepEqual(k.Public(), cert.PublicKey)
	default:
		return false
	}
}


// ValidateBytes performs full validation of in-memory certificate and private key against a given hostname.
func ValidateBytes(certPEM, keyPEM []byte, hostname string) (*CertificateReport, *Certificate, error) {
	report := &CertificateReport{
		Hostname: hostname,
		Exists:   true,
	}

	// 1. Parse Certificate(s)
	certs, err := ParseCertificates(certPEM)
	if err != nil {
		report.Message = fmt.Sprintf("Certificate parse error: %v", err)
		return report, nil, err
	}
	report.CertificateOK = true
	primaryCert := certs[0]

	// 2. Parse Private Key
	privKey, err := ParsePrivateKey(keyPEM)
	if err != nil {
		report.Message = fmt.Sprintf("Private key parse error: %v", err)
		return report, nil, err
	}
	report.PrivateKeyOK = true

	// 3. Key Match Check
	if !PublicKeyMatches(primaryCert, privKey) {
		report.KeyMatches = false
		report.Message = "Certificate public key does not match private key"
		return report, nil, ErrKeyMismatch
	}
	report.KeyMatches = true

	// 4. Hostname Validation
	if hostname != "" {
		if err := primaryCert.VerifyHostname(hostname); err != nil {
			report.HostnameMatches = false
			report.Message = fmt.Sprintf("Hostname %q does not match certificate SAN/CN: %v", hostname, err)
			return report, nil, ErrHostnameMismatch
		}
	}
	report.HostnameMatches = true

	// 5. Expiration & Validity
	now := time.Now()
	expired := now.Before(primaryCert.NotBefore) || now.After(primaryCert.NotAfter)
	daysRemaining := int(primaryCert.NotAfter.Sub(now).Hours() / 24)

	report.Expired = expired
	report.DaysRemaining = daysRemaining
	report.Status = CalculateExpirationStatus(daysRemaining, expired)
	report.Issuer = primaryCert.Issuer.CommonName
	if report.Issuer == "" && len(primaryCert.Issuer.Organization) > 0 {
		report.Issuer = primaryCert.Issuer.Organization[0]
	}
	report.NotAfter = primaryCert.NotAfter

	if expired {
		report.Message = fmt.Sprintf("Certificate expired or not yet valid (valid: %s to %s)", primaryCert.NotBefore.Format("2006-01-02"), primaryCert.NotAfter.Format("2006-01-02"))
		return report, nil, ErrCertificateExpired
	}

	hash := sha256.Sum256(primaryCert.Raw)
	fingerprint := strings.ToUpper(hex.EncodeToString(hash[:]))

	certModel := &Certificate{
		Hostname:    hostname,
		Issuer:      report.Issuer,
		Subject:     primaryCert.Subject.CommonName,
		DNSNames:    primaryCert.DNSNames,
		NotBefore:   primaryCert.NotBefore,
		NotAfter:    primaryCert.NotAfter,
		Fingerprint: fingerprint,
	}

	return report, certModel, nil
}
