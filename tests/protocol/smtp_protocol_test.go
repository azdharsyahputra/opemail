package protocol_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	"net"
	"net/smtp"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/azdharsyahputra/openmail/internal/config"
	"github.com/azdharsyahputra/openmail/internal/database"
	"github.com/azdharsyahputra/openmail/internal/domain"
	"github.com/azdharsyahputra/openmail/internal/mailbox"
	"github.com/azdharsyahputra/openmail/internal/provisioning"
	"github.com/google/uuid"
)

func setupProtocolTestDB(t *testing.T) (*sql.DB, string) {

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		cfg, err := config.Load()
		if err == nil && cfg.DatabaseURL != "" {
			dbURL = cfg.DatabaseURL
		} else {
			dbURL = "postgres://mailopen:mailopen@localhost:5433/mailopen?sslmode=disable"
		}
	}

	db, err := database.NewPostgresDB(dbURL)
	if err != nil {
		t.Skipf("Skipping protocol test: PostgreSQL unavailable (%v)", err)
		return nil, ""
	}

	if err := database.RunMigrationsUp(db); err != nil {
		t.Fatalf("failed to run migrations up: %v", err)
	}

	testDomain := fmt.Sprintf("proto-%d.example.com", time.Now().UnixNano())
	domRepo := domain.NewPostgresRepository(db)
	_ = domRepo.Create(context.Background(), &domain.Domain{ID: uuid.New(), Name: testDomain, Status: "active"})

	return db, testDomain
}

func TestSMTP_ProtocolCompliance(t *testing.T) {
	conn25, err := net.DialTimeout("tcp", "127.0.0.1:25", 500*time.Millisecond)
	if err != nil {
		t.Skip("Inbound SMTP port :25 not reachable on localhost, skipping live protocol test")
		return
	}
	_ = conn25.Close()

	db, testDomain := setupProtocolTestDB(t)
	if db == nil {
		return
	}
	defer db.Close()

	ctx := context.Background()
	domRepo := domain.NewPostgresRepository(db)
	mbRepo := mailbox.NewPostgresRepository(db)
	prov, _ := provisioning.NewFilesystemProvisioner(os.TempDir(), 5000, 5000)
	mbSvc := mailbox.NewService(mbRepo, domRepo, prov)

	validEmail := "receiver@" + testDomain
	_, _ = mbSvc.Create(ctx, validEmail, "SecretPass123!", 1073741824)

	// PROTO-001: Standard Command Set (EHLO, HELO, NOOP, RSET, QUIT)
	t.Run("PROTO-001 & PROTO-003: Command Set & RSET Reset", func(t *testing.T) {
		conn, err := net.Dial("tcp", "127.0.0.1:25")
		if err != nil {
			t.Fatalf("dial error: %v", err)
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		banner, _ := reader.ReadString('\n')
		if !strings.HasPrefix(banner, "220") {
			t.Fatalf("unexpected banner: %s", banner)
		}

		// Send EHLO
		fmt.Fprintf(conn, "EHLO client.test.com\r\n")
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("read error: %v", err)
			}
			if len(line) >= 4 && line[3] == ' ' {
				break // end of multiline EHLO
			}
		}

		// NOOP
		fmt.Fprintf(conn, "NOOP\r\n")
		noopResp, _ := reader.ReadString('\n')
		if !strings.HasPrefix(noopResp, "250") {
			t.Errorf("NOOP failed: %s", noopResp)
		}

		// Start MAIL FROM then RSET
		fmt.Fprintf(conn, "MAIL FROM:<sender@test.com>\r\n")
		mailResp, _ := reader.ReadString('\n')
		if !strings.HasPrefix(mailResp, "250") {
			t.Errorf("MAIL FROM failed: %s", mailResp)
		}

		// RSET
		fmt.Fprintf(conn, "RSET\r\n")
		rsetResp, _ := reader.ReadString('\n')
		if !strings.HasPrefix(rsetResp, "250") {
			t.Errorf("RSET failed: %s", rsetResp)
		}

		// DATA immediately after RSET must be rejected
		fmt.Fprintf(conn, "DATA\r\n")
		dataResp, _ := reader.ReadString('\n')
		if strings.HasPrefix(dataResp, "354") {
			t.Errorf("DATA should fail after RSET: %s", dataResp)
		}

		// QUIT
		fmt.Fprintf(conn, "QUIT\r\n")
		quitResp, _ := reader.ReadString('\n')
		if !strings.HasPrefix(quitResp, "221") {
			t.Errorf("QUIT failed: %s", quitResp)
		}
	})

	// PROTO-004 & PROTO-005: Multiple consecutive MAIL FROM and multiple RCPT
	t.Run("PROTO-004 & PROTO-005: Multiple Recipients & Transactions", func(t *testing.T) {
		c, err := smtp.Dial("127.0.0.1:25")
		if err != nil {
			t.Fatalf("smtp dial failed: %v", err)
		}
		defer c.Close()

		_ = c.Hello("client.test.com")
		_ = c.StartTLS(&tls.Config{InsecureSkipVerify: true})

		if err := c.Mail("sender@partner.com"); err != nil {
			t.Fatalf("MAIL FROM failed: %v", err)
		}

		// Valid recipient
		if err := c.Rcpt(validEmail); err != nil {
			t.Fatalf("RCPT TO valid failed: %v", err)
		}

		// Invalid recipient in same transaction -> 550
		if err := c.Rcpt("ghost@" + testDomain); err == nil {
			t.Errorf("expected ghost recipient to be rejected")
		}

		w, err := c.Data()
		if err != nil {
			t.Fatalf("DATA failed: %v", err)
		}
		_, _ = fmt.Fprintf(w, "Subject: PROTO-005 Test\r\n\r\nMulti-rcpt payload\r\n")
		_ = w.Close()

		// Transaction 2 in same connection
		if err := c.Mail("sender2@partner.com"); err != nil {
			t.Fatalf("second MAIL FROM failed: %v", err)
		}
		if err := c.Rcpt(validEmail); err != nil {
			t.Fatalf("second RCPT failed: %v", err)
		}
		w2, err := c.Data()
		if err != nil {
			t.Fatalf("second DATA failed: %v", err)
		}
		_, _ = fmt.Fprintf(w2, "Subject: Transaction 2\r\n\r\nBody 2\r\n")
		_ = w2.Close()
	})

	// SMTP-008: Open Relay rejection on :25
	t.Run("SMTP-008: Open Relay Prohibited", func(t *testing.T) {
		c, err := smtp.Dial("127.0.0.1:25")
		if err != nil {
			t.Fatalf("dial failed: %v", err)
		}
		defer c.Close()

		_ = c.Hello("attacker.com")
		_ = c.Mail("attacker@evil.com")
		err = c.Rcpt("someone@gmail.com")
		if err == nil {
			t.Errorf("expected open relay attempt to gmail.com to be rejected on :25")
		} else if !strings.Contains(err.Error(), "554") && !strings.Contains(err.Error(), "Relay") {
			t.Errorf("expected 554 Relay access denied, got: %v", err)
		}
	})
}
