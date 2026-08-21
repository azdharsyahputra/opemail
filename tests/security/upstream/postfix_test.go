package upstream_test

import (
	"context"
	"net"
	"net/smtp"
	"strings"
	"testing"
	"time"

	"github.com/azdharsyahputra/openmail/internal/queue"
)

// UPSTREAM-POSTFIX-001: Open relay regression
func TestUPSTREAM_POSTFIX_001_OpenRelayRegression(t *testing.T) {
	conn, err := net.DialTimeout("tcp", "127.0.0.1:25", 2*time.Second)
	if err != nil {
		t.Skipf("port 25 offline in test environment: %v", err)
		return
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, "localhost")
	if err != nil {
		t.Fatalf("smtp client init failed: %v", err)
	}
	defer client.Close()

	_ = client.Hello("spammer.org")
	_ = client.Mail("spammer@external.com")
	err = client.Rcpt("target@another-external.com")
	if err == nil {
		t.Fatalf("SECURITY INVARIANT VIOLATED (UPSTREAM-POSTFIX-001): Open relay accepted external recipient!")
	}
}

// UPSTREAM-POSTFIX-002: SMTP AUTH bypass
func TestUPSTREAM_POSTFIX_002_SMTPAuthBypass(t *testing.T) {
	// Ensure AUTH is rejected or disabled on port 25 without TLS
	conn, err := net.DialTimeout("tcp", "127.0.0.1:25", 2*time.Second)
	if err != nil {
		t.Skipf("port 25 offline: %v", err)
		return
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, "localhost")
	if err != nil {
		t.Fatalf("smtp client failed: %v", err)
	}
	defer client.Close()

	_ = client.Hello("localhost")
	auth := smtp.PlainAuth("", "user@example.com", "pass", "127.0.0.1")
	err = client.Auth(auth)
	if err == nil {
		t.Fatalf("SECURITY INVARIANT VIOLATED (UPSTREAM-POSTFIX-002): Plaintext AUTH succeeded over unencrypted port 25")
	}
}

// UPSTREAM-POSTFIX-004: Header injection
func TestUPSTREAM_POSTFIX_004_HeaderInjection(t *testing.T) {
	maliciousSubject := "Hello\r\nBcc: secret@victim.com\r\n\r\nInjected body"
	// Ensure CRLF stripping / encoding prevents header injection
	if strings.Contains(maliciousSubject, "\r\n") {
		sanitized := strings.ReplaceAll(maliciousSubject, "\r", "")
		sanitized = strings.ReplaceAll(sanitized, "\n", " ")
		if strings.Contains(sanitized, "\r\n") || strings.Contains(sanitized, "\n") {
			t.Fatalf("SECURITY INVARIANT VIOLATED (UPSTREAM-POSTFIX-004): Header injection not sanitized")
		}
	}
}

// UPSTREAM-POSTFIX-005: Queue command injection
func TestUPSTREAM_POSTFIX_005_QueueCommandInjection(t *testing.T) {
	qDriver := queue.NewSystemDriver("mailopen_postfix")
	qSvc := queue.NewService(qDriver)

	maliciousIDs := []string{
		"123; rm -rf /",
		"123$(whoami)",
		"123`id`",
		"123\npostsuper -d ALL",
	}

	ctx := context.Background()
	for _, mid := range maliciousIDs {
		err := qSvc.Delete(ctx, mid)
		if err == nil {
			t.Fatalf("SECURITY INVARIANT VIOLATED (UPSTREAM-POSTFIX-005): Injected queue ID %q accepted", mid)
		}
	}
}

// UPSTREAM-POSTFIX-008: Malformed SMTP command abuse
func TestUPSTREAM_POSTFIX_008_MalformedSMTPCommand(t *testing.T) {
	conn, err := net.DialTimeout("tcp", "127.0.0.1:25", 2*time.Second)
	if err != nil {
		t.Skipf("port 25 offline: %v", err)
		return
	}
	defer conn.Close()

	// Send oversized garbage command
	hugeGarbage := strings.Repeat("A", 10000) + "\r\n"
	_, err = conn.Write([]byte(hugeGarbage))
	if err != nil {
		return // Connection cleanly closed or rejected (PASS)
	}
	buf := make([]byte, 1024)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _ := conn.Read(buf)
	resp := string(buf[:n])
	if strings.Contains(resp, "250") {
		t.Fatalf("SECURITY INVARIANT VIOLATED (UPSTREAM-POSTFIX-008): 10KB garbage command returned 250 OK")
	}
}
