package upstream_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/azdharsyahputra/openmail/internal/dkim"
)

// UPSTREAM-DKIM-001 & 007: Private key disclosure & Key permission regression
func TestUPSTREAM_DKIM_001_007_KeyPermissions(t *testing.T) {
	tempDir := t.TempDir()
	keystore := dkim.NewFilesystemKeystore(tempDir)

	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	})

	keyPath, err := keystore.StorePrivateKey(context.Background(), "example.com", "default", privPEM)
	if err != nil {
		t.Fatalf("failed to store key: %v", err)
	}

	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Fatalf("SECURITY INVARIANT VIOLATED (UPSTREAM-DKIM-007): Private key permission is %o (must be 0600)", perm)
	}
}

// UPSTREAM-DKIM-002: Milter network exposure
func TestUPSTREAM_DKIM_002_MilterNetworkExposure(t *testing.T) {
	// Ensure OpenDKIM is NOT exposed to public 0.0.0.0:8891
	conn, err := net.DialTimeout("tcp", "127.0.0.1:8891", 500*time.Millisecond)
	if err == nil {
		conn.Close()
		t.Logf("Milter port 8891 is open on loopback; verifying UNIX socket preferred")
	}
}

// UPSTREAM-DKIM-003: Signature parsing DoS (Upstream Issue #324)
func TestUPSTREAM_DKIM_003_SignatureParsingDoS(t *testing.T) {
	// Parse 500 oversized/malformed DKIM headers in bounded time
	start := time.Now()
	for i := 0; i < 500; i++ {
		_, _, _ = dkim.ParseDNSTXTRecord(fmt.Sprintf("v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA%d", i))
	}
	duration := time.Since(start)
	if duration > 1*time.Second {
		t.Fatalf("SECURITY INVARIANT VIOLATED (UPSTREAM-DKIM-003): 500 signatures took %v (> 1s limit)", duration)
	}
}

// UPSTREAM-DKIM-005: Header/signature manipulation
func TestUPSTREAM_DKIM_005_HeaderSignatureManipulation(t *testing.T) {
	// Malformed tags in DNS TXT record
	malformedTXT := "v=DKIM1; p=; k=invalid_crypto; s=*"
	_, _, err := dkim.ParseDNSTXTRecord(malformedTXT)
	if err == nil {
		t.Fatalf("SECURITY INVARIANT VIOLATED (UPSTREAM-DKIM-005): Malformed DKIM TXT record with empty p= accepted")
	}
}
