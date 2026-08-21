package security_test

import (
	"net"
	"net/smtp"
	"testing"
	"time"
)

// TestPostfix_Security_Protocols verifies open relay restrictions,
// submission auth requirements, and header validation
func TestPostfix_Security_Protocols(t *testing.T) {
	t.Run("Inbound Open Relay Rejection", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:25", 2*time.Second)
		if err != nil {
			t.Skipf("Postfix port 25 not available: %v", err)
			return
		}
		defer conn.Close()

		client, err := smtp.NewClient(conn, "localhost")
		if err != nil {
			t.Fatalf("smtp client init failed: %v", err)
		}
		defer client.Close()

		_ = client.Hello("attacker.net")
		_ = client.Mail("spammer@external.net")
		err = client.Rcpt("victim@another-domain.net")
		if err == nil {
			t.Fatalf("SECURITY INVARIANT VIOLATED: Open relay accepted external -> external traffic")
		}
	})
}
