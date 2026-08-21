package tls_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/azdharsyahputra/openmail/internal/tls"
)

func generateTestCert(t *testing.T, hostname string, validFrom, validTo time.Time, isRSA bool) ([]byte, []byte) {
	t.Helper()

	var privKey any
	var pubKey any
	var privBytes []byte

	if isRSA {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("generate rsa key: %v", err)
		}
		privKey = key
		pubKey = &key.PublicKey
		privBytes = x509.MarshalPKCS1PrivateKey(key)
	} else {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate ec key: %v", err)
		}
		privKey = key
		pubKey = &key.PublicKey
		b, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			t.Fatalf("marshal ec key: %v", err)
		}
		privBytes = b
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   hostname,
			Organization: []string{"MailOpen Test CA"},
		},
		NotBefore:             validFrom,
		NotAfter:              validTo,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{hostname, "mail.example.com"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, pubKey, privKey)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyType := "EC PRIVATE KEY"
	if isRSA {
		keyType = "RSA PRIVATE KEY"
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: keyType, Bytes: privBytes})

	return certPEM, keyPEM
}

func TestTLSValidatorMatrix(t *testing.T) {
	now := time.Now()

	t.Run("Valid RSA Certificate -> PASS", func(t *testing.T) {
		certPEM, keyPEM := generateTestCert(t, "mail.example.com", now.Add(-1*time.Hour), now.Add(90*24*time.Hour), true)
		report, cert, err := tls.ValidateBytes(certPEM, keyPEM, "mail.example.com")
		if err != nil {
			t.Fatalf("expected valid cert, got err: %v", err)
		}
		if !report.CertificateOK || !report.PrivateKeyOK || !report.KeyMatches || !report.HostnameMatches {
			t.Errorf("expected all checks true, got report: %+v", report)
		}
		if cert.Hostname != "mail.example.com" {
			t.Errorf("expected hostname mail.example.com, got %s", cert.Hostname)
		}
		if report.Status != tls.StatusHealthy {
			t.Errorf("expected StatusHealthy, got %s", report.Status)
		}
	})

	t.Run("Valid ECDSA Certificate -> PASS", func(t *testing.T) {
		certPEM, keyPEM := generateTestCert(t, "mail.example.com", now.Add(-1*time.Hour), now.Add(90*24*time.Hour), false)
		report, _, err := tls.ValidateBytes(certPEM, keyPEM, "mail.example.com")
		if err != nil {
			t.Fatalf("expected valid ecdsa cert, got err: %v", err)
		}
		if !report.KeyMatches {
			t.Errorf("expected key match for ECDSA")
		}
	})

	t.Run("Certificate/Key Mismatch -> FAIL", func(t *testing.T) {
		certPEM1, _ := generateTestCert(t, "mail.example.com", now.Add(-1*time.Hour), now.Add(90*24*time.Hour), true)
		_, keyPEM2 := generateTestCert(t, "mail.example.com", now.Add(-1*time.Hour), now.Add(90*24*time.Hour), true)

		report, _, err := tls.ValidateBytes(certPEM1, keyPEM2, "mail.example.com")
		if err != tls.ErrKeyMismatch {
			t.Errorf("expected ErrKeyMismatch, got %v", err)
		}
		if report.KeyMatches {
			t.Errorf("expected KeyMatches to be false")
		}
	})

	t.Run("Hostname Mismatch -> FAIL", func(t *testing.T) {
		certPEM, keyPEM := generateTestCert(t, "other.example.com", now.Add(-1*time.Hour), now.Add(90*24*time.Hour), true)
		report, _, err := tls.ValidateBytes(certPEM, keyPEM, "bank.google.com")
		if err != tls.ErrHostnameMismatch {
			t.Errorf("expected ErrHostnameMismatch, got %v", err)
		}
		if report.HostnameMatches {
			t.Errorf("expected HostnameMatches to be false")
		}
	})

	t.Run("Expired Certificate -> FAIL", func(t *testing.T) {
		certPEM, keyPEM := generateTestCert(t, "mail.example.com", now.Add(-10*24*time.Hour), now.Add(-1*24*time.Hour), true)
		report, _, err := tls.ValidateBytes(certPEM, keyPEM, "mail.example.com")
		if err != tls.ErrCertificateExpired {
			t.Errorf("expected ErrCertificateExpired, got %v", err)
		}
		if !report.Expired {
			t.Errorf("expected Expired to be true")
		}
		if report.Status != tls.StatusExpired {
			t.Errorf("expected StatusExpired, got %s", report.Status)
		}
	})
}

func TestFilesystemProvider_AtomicInstall(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "openmail-tls-test-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	provider := tls.NewFilesystemProvider(tempDir)
	service := tls.NewService(provider)
	ctx := context.Background()
	now := time.Now()

	certPEM, keyPEM := generateTestCert(t, "mail.example.com", now.Add(-1*time.Hour), now.Add(60*24*time.Hour), true)

	// Save temporary files
	certFile := filepath.Join(tempDir, "source_fullchain.pem")
	keyFile := filepath.Join(tempDir, "source_privkey.pem")
	_ = os.WriteFile(certFile, certPEM, 0644)
	_ = os.WriteFile(keyFile, keyPEM, 0600)

	t.Run("Install valid certificate", func(t *testing.T) {
		report, err := service.Install(ctx, "mail.example.com", certFile, keyFile)
		if err != nil {
			t.Fatalf("Install failed: %v", err)
		}
		if !report.CertificateOK || !report.KeyMatches {
			t.Errorf("expected successful install report")
		}

		// Verify installed files & permissions
		certPath, keyPath := provider.GetPaths("mail.example.com")
		certInfo, err := os.Stat(certPath)
		if err != nil || certInfo.Mode().Perm() != 0644 {
			t.Errorf("cert file missing or invalid perm: %v (perm: %04o)", err, certInfo.Mode().Perm())
		}

		keyInfo, err := os.Stat(keyPath)
		if err != nil || keyInfo.Mode().Perm() != 0600 {
			t.Errorf("key file missing or invalid perm: %v (perm: %04o)", err, keyInfo.Mode().Perm())
		}
	})

	t.Run("Invalid certificate does not overwrite active cert", func(t *testing.T) {
		// Read current valid cert bytes
		activeCertPath, _ := provider.GetPaths("mail.example.com")
		activeCertBefore, _ := os.ReadFile(activeCertPath)

		// Create broken key file
		badKeyFile := filepath.Join(tempDir, "bad_key.pem")
		_ = os.WriteFile(badKeyFile, []byte("NOT A VALID KEY"), 0600)

		_, err := service.Install(ctx, "mail.example.com", certFile, badKeyFile)
		if err == nil {
			t.Fatalf("expected install with bad key to fail")
		}

		// Verify active cert was NOT replaced
		activeCertAfter, _ := os.ReadFile(activeCertPath)
		if !bytes.Equal(activeCertBefore, activeCertAfter) {
			t.Errorf("active certificate was modified despite validation failure")
		}
	})
}
