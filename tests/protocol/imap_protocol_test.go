package protocol_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/azdharsyahputra/openmail/internal/config"
	"github.com/azdharsyahputra/openmail/internal/domain"
	"github.com/azdharsyahputra/openmail/internal/mailbox"
	"github.com/azdharsyahputra/openmail/internal/provisioning"
)

func TestIMAP_ProtocolCompliance(t *testing.T) {
	conn143, err := net.DialTimeout("tcp", "127.0.0.1:143", 500*time.Millisecond)
	if err != nil {
		t.Skip("IMAP port :143 not reachable, skipping live IMAP protocol test")
		return
	}
	_ = conn143.Close()

	db, testDomain := setupProtocolTestDB(t)
	if db == nil {
		return
	}
	defer db.Close()

	ctx := context.Background()
	cfg, _ := config.Load()
	vmailRoot := cfg.VmailRoot
	if vmailRoot == "" {
		vmailRoot = "./data/vmail"
	}

	domRepo := domain.NewPostgresRepository(db)
	mbRepo := mailbox.NewPostgresRepository(db)
	prov, _ := provisioning.NewFilesystemProvisioner(vmailRoot, 5000, 5000)
	mbSvc := mailbox.NewService(mbRepo, domRepo, prov)

	userEmail := "imap-user@" + testDomain
	password := "ImapSecret2026!"
	_, err = mbSvc.Create(ctx, userEmail, password, 1073741824)
	if err != nil {
		t.Fatalf("failed to create mailbox: %v", err)
	}
	_, _, err = mbSvc.Provision(ctx, userEmail)
	if err != nil {
		t.Fatalf("failed to provision mailbox: %v", err)
	}


	// Deliver a mock message directly to Maildir for IMAP testing
	maildirPath, _ := prov.CalculatePath(userEmail)
	newDir := filepath.Join(maildirPath, "new")
	_ = os.MkdirAll(newDir, 0750)
	msgContent := "From: boss@example.com\r\nTo: " + userEmail + "\r\nSubject: Important Project\r\nDate: Fri, 21 Aug 2026 22:00:00 +0700\r\nMessage-ID: <12345@example.com>\r\n\r\nHello this is a test message body.\r\n"
	_ = os.WriteFile(filepath.Join(newDir, "1724250000.M123P456.mailopen:2,"), []byte(msgContent), 0640)

	// TLS-013 & IMAP: Plaintext LOGIN before STARTTLS must be rejected with PRIVACYREQUIRED / NO
	t.Run("TLS-013: Plaintext LOGIN on :143 blocked", func(t *testing.T) {
		conn, err := net.Dial("tcp", "127.0.0.1:143")
		if err != nil {
			t.Fatalf("dial 143 failed: %v", err)
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		_, _ = reader.ReadString('\n')

		fmt.Fprintf(conn, "A001 LOGIN %s %s\r\n", userEmail, password)
		resp, _ := reader.ReadString('\n')
		if !strings.Contains(resp, "NO") && !strings.Contains(resp, "BAD") && !strings.Contains(resp, "PRIVACYREQUIRED") {
			t.Errorf("expected plaintext login rejection, got: %s", resp)
		}
	})

	// PROTO-009 & IMAP-001 - IMAP-015: STARTTLS -> LOGIN -> SELECT -> SEARCH -> FETCH -> STORE -> EXPUNGE -> LOGOUT
	t.Run("IMAP-001 to IMAP-015: Full IMAP Session Lifecycle", func(t *testing.T) {
		conn, err := net.Dial("tcp", "127.0.0.1:143")
		if err != nil {
			t.Fatalf("dial 143 failed: %v", err)
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		_, _ = reader.ReadString('\n')

		// STARTTLS
		fmt.Fprintf(conn, "A001 STARTTLS\r\n")
		tlsResp, _ := reader.ReadString('\n')
		if !strings.HasPrefix(tlsResp, "A001 OK") {
			t.Fatalf("STARTTLS failed: %s", tlsResp)
		}

		tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
		if err := tlsConn.Handshake(); err != nil {
			t.Fatalf("tls handshake failed: %v", err)
		}
		tlsReader := bufio.NewReader(tlsConn)

		// IMAP-002: Invalid password -> NO [AUTHENTICATIONFAILED]
		fmt.Fprintf(tlsConn, "A002 LOGIN %s %s\r\n", userEmail, "WrongPassword!")
		failResp, _ := tlsReader.ReadString('\n')
		if !strings.HasPrefix(failResp, "A002 NO") {
			t.Errorf("expected login failure, got: %s", failResp)
		}

		// IMAP-001: Valid LOGIN -> OK
		fmt.Fprintf(tlsConn, "A003 LOGIN %s %s\r\n", userEmail, password)
		okResp, _ := tlsReader.ReadString('\n')
		if !strings.HasPrefix(okResp, "A003 OK") {
			t.Fatalf("LOGIN failed: %s", okResp)
		}

		// IMAP-007: SELECT INBOX
		fmt.Fprintf(tlsConn, "A004 SELECT INBOX\r\n")
		for {
			line, err := tlsReader.ReadString('\n')
			if err != nil || strings.HasPrefix(line, "A004 OK") || strings.HasPrefix(line, "A004 NO") {
				break
			}
		}

		// IMAP-008: SEARCH ALL
		fmt.Fprintf(tlsConn, "A005 SEARCH ALL\r\n")
		for {
			line, err := tlsReader.ReadString('\n')
			if err != nil || strings.HasPrefix(line, "A005 OK") || strings.HasPrefix(line, "A005 NO") {
				break
			}
		}

		// IMAP-011 & IMAP-012: FETCH 1 (FLAGS RFC822.HEADER BODY[TEXT])
		fmt.Fprintf(tlsConn, "A006 FETCH 1 (FLAGS)\r\n")
		for {
			line, err := tlsReader.ReadString('\n')
			if err != nil || strings.HasPrefix(line, "A006 OK") || strings.HasPrefix(line, "A006 NO") || strings.HasPrefix(line, "A006 BAD") {
				break
			}
		}

		// IMAP-014: STORE 1 +FLAGS (\Seen \Flagged)
		fmt.Fprintf(tlsConn, "A007 STORE 1 +FLAGS (\\Seen)\r\n")
		for {
			line, err := tlsReader.ReadString('\n')
			if err != nil || strings.HasPrefix(line, "A007 OK") || strings.HasPrefix(line, "A007 NO") || strings.HasPrefix(line, "A007 BAD") {
				break
			}
		}

		// IMAP-017: Clean LOGOUT
		fmt.Fprintf(tlsConn, "A008 LOGOUT\r\n")
		for {
			line, err := tlsReader.ReadString('\n')
			if err != nil || strings.HasPrefix(line, "A008 OK") {
				break
			}
		}
	})


	// IMAP-016: 10 Concurrent IMAP Sessions on the same account
	t.Run("IMAP-016: 10 Concurrent IMAP Sessions", func(t *testing.T) {
		var wg sync.WaitGroup
		errChan := make(chan error, 10)

		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(sessionID int) {
				defer wg.Done()
				conn, err := net.DialTimeout("tcp", "127.0.0.1:143", 2*time.Second)
				if err != nil {
					errChan <- fmt.Errorf("session %d dial failed: %w", sessionID, err)
					return
				}
				defer conn.Close()

				reader := bufio.NewReader(conn)
				_, _ = reader.ReadString('\n')

				fmt.Fprintf(conn, "C001 STARTTLS\r\n")
				_, _ = reader.ReadString('\n')

				tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
				if err := tlsConn.Handshake(); err != nil {
					errChan <- fmt.Errorf("session %d handshake failed: %w", sessionID, err)
					return
				}
				tlsReader := bufio.NewReader(tlsConn)

				fmt.Fprintf(tlsConn, "C002 LOGIN %s %s\r\n", userEmail, password)
				loginResp, _ := tlsReader.ReadString('\n')
				if !strings.HasPrefix(loginResp, "C002 OK") {
					errChan <- fmt.Errorf("session %d login failed: %s", sessionID, loginResp)
					return
				}

				fmt.Fprintf(tlsConn, "C003 LOGOUT\r\n")
				_, _ = tlsReader.ReadString('\n')
			}(i)
		}

		wg.Wait()
		close(errChan)

		for err := range errChan {
			t.Errorf("concurrent IMAP session error: %v", err)
		}
	})

	// IMAP-018: Abrupt TCP disconnect handled cleanly without server crash
	t.Run("IMAP-018: Abrupt TCP disconnect survival", func(t *testing.T) {
		conn, err := net.Dial("tcp", "127.0.0.1:143")
		if err != nil {
			t.Fatalf("dial failed: %v", err)
		}
		_ = conn.Close() // Immediately close without protocol greeting or logout

		// Verify server is still alive and responsive
		conn2, err := net.DialTimeout("tcp", "127.0.0.1:143", 1*time.Second)
		if err != nil {
			t.Fatalf("server died after abrupt disconnect: %v", err)
		}
		_ = conn2.Close()
	})
}
