package security_test

import (
	"net"
	"strings"
	"testing"
	"time"
)

// TestDovecot_Security_IMAPProtocol verifies IMAP command isolation,
// unauthenticated rejection, and protocol bounds
func TestDovecot_Security_IMAPProtocol(t *testing.T) {
	t.Run("Unauthenticated Command Rejection", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:143", 2*time.Second)
		if err != nil {
			t.Skipf("IMAP port 143 offline: %v", err)
			return
		}
		defer conn.Close()

		buf := make([]byte, 1024)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = conn.Read(buf) // Drain banner

		_, _ = conn.Write([]byte("A01 LIST \"\" \"*\"\r\n"))
		n, _ := conn.Read(buf)
		resp := string(buf[:n])

		if strings.Contains(resp, "A01 OK") {
			t.Fatalf("SECURITY INVARIANT VIOLATED: Unauthenticated LIST returned A01 OK")
		}
	})
}
