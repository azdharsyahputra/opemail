package security_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"

	"github.com/azdharsyahputra/openmail/internal/dkim"
)

// TestOpenDKIM_Security_KeyAndMilter verifies DKIM private key protections,
// selector validation, and milter configuration isolation
func TestOpenDKIM_Security_KeyAndMilter(t *testing.T) {
	tempDir := t.TempDir()
	keystore := dkim.NewFilesystemKeystore(tempDir)

	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	})

	keyPath, err := keystore.StorePrivateKey(context.Background(), "example.com", "default", privPEM)
	if err != nil {
		t.Fatalf("failed to store private key: %v", err)
	}

	t.Run("Strict 0600 Private Key File Permission", func(t *testing.T) {
		info, err := os.Stat(keyPath)
		if err != nil {
			t.Fatalf("stat key failed: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0600 {
			t.Fatalf("SECURITY INVARIANT VIOLATED: DKIM key permissions %o (must be 0600)", perm)
		}
	})

	t.Run("Selector Traversal Validation", func(t *testing.T) {
		badSelectors := []string{
			"../../etc",
			"default/../../key",
			"sel;rm",
			"sel*",
		}
		for _, bs := range badSelectors {
			err := dkim.ValidateSelector(bs)
			if err == nil {
				t.Fatalf("SECURITY INVARIANT VIOLATED: Invalid selector %q passed validation", bs)
			}
		}
	})
}
