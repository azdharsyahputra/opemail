package dovecot_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/azdharsyahputra/openmail/internal/dovecot"
	"github.com/azdharsyahputra/openmail/internal/mailbox"
)

type mockDovecotRepo struct {
	users map[string]*dovecot.UserInfo
	hashes map[string]string
}

func newMockDovecotRepo() *mockDovecotRepo {
	return &mockDovecotRepo{
		users:  make(map[string]*dovecot.UserInfo),
		hashes: make(map[string]string),
	}
}

func (m *mockDovecotRepo) GetPasswordHash(ctx context.Context, username string) (string, error) {
	username = strings.ToLower(username)
	hash, ok := m.hashes[username]
	if !ok {
		return "", dovecot.ErrUserNotFound
	}
	return hash, nil
}

func (m *mockDovecotRepo) GetUserInfo(ctx context.Context, username string, vmailRoot string, uid, gid int) (*dovecot.UserInfo, error) {
	username = strings.ToLower(username)
	user, ok := m.users[username]
	if !ok {
		return nil, dovecot.ErrUserNotFound
	}
	return user, nil
}

func TestDovecotConfigGeneration(t *testing.T) {
	opts := dovecot.ConfigOptions{
		ConfigDir:        "/etc/dovecot",
		TargetConfigPath: "/etc/dovecot",
		VmailRoot:        "/var/vmail",
		VmailUID:         5000,
		VmailGID:         5000,
		DBHost:           "127.0.0.1",
		DBPort:           5432,
		DBName:           "mailopen",
		DBUser:           "mailopen_dovecot",
		DBPassword:       "secretpassword",
	}

	configs := dovecot.GenerateConfigs(opts)

	t.Run("dovecot.conf contains protocols = imap", func(t *testing.T) {
		if !strings.Contains(configs.DovecotConf, "protocols = imap") {
			t.Error("dovecot.conf missing protocols = imap")
		}
	})

	t.Run("10-mail.conf contains mail_location maildir and vmail uid/gid", func(t *testing.T) {
		if !strings.Contains(configs.MailConf, "mail_location = maildir:/var/vmail/%d/%n/Maildir") {
			t.Error("10-mail.conf missing correct mail_location format")
		}
		if !strings.Contains(configs.MailConf, "mail_uid = 5000") || !strings.Contains(configs.MailConf, "mail_gid = 5000") {
			t.Error("10-mail.conf missing mail_uid/gid 5000")
		}
	})

	t.Run("10-auth.conf enables plain/login and auth_username_format", func(t *testing.T) {
		if !strings.Contains(configs.AuthConf, "auth_mechanisms = plain login") {
			t.Error("10-auth.conf missing plain login mechanisms")
		}
		if !strings.Contains(configs.AuthConf, "auth_username_format = %Lu") {
			t.Error("10-auth.conf missing %Lu lowercase username normalization")
		}
	})

	t.Run("dovecot-pgsql.conf.ext has Argon2id passdb and userdb queries", func(t *testing.T) {
		if !strings.Contains(configs.PgSQLConf, "default_pass_scheme = ARGON2ID") {
			t.Error("dovecot-pgsql missing default_pass_scheme = ARGON2ID")
		}
		if !strings.Contains(configs.PgSQLConf, "password_query = SELECT email AS username, password_hash AS password") {
			t.Error("dovecot-pgsql missing password_query")
		}
		if !strings.Contains(configs.PgSQLConf, "user_query = SELECT 5000 AS uid, 5000 AS gid, '/var/vmail/%d/%n/Maildir' AS home") {
			t.Error("dovecot-pgsql missing user_query")
		}
	})

	t.Run("WriteConfigsAtomically creates 0640 permission for pgsql credential file", func(t *testing.T) {
		tempDir, err := os.MkdirTemp("", "openmail-dovecot-test-*")
		if err != nil {
			t.Fatalf("failed to create temp dir: %v", err)
		}
		defer os.RemoveAll(tempDir)

		opts.ConfigDir = tempDir
		err = dovecot.WriteConfigsAtomically(opts)
		if err != nil {
			t.Fatalf("WriteConfigsAtomically failed: %v", err)
		}

		pgsqlPath := filepath.Join(tempDir, "sql", "dovecot-pgsql.conf.ext")
		info, err := os.Stat(pgsqlPath)
		if err != nil {
			t.Fatalf("expected sql credential file to exist: %v", err)
		}
		if perm := info.Mode().Perm(); perm > 0640 {
			t.Errorf("expected pgsql config perm <= 0640, got %04o", perm)
		}
	})
}

func TestDovecotAuthenticationMatrix(t *testing.T) {
	repo := newMockDovecotRepo()
	prov := dovecot.NewSystemProvisioner("/tmp")
	svc := dovecot.NewService(repo, prov)
	ctx := context.Background()

	rawPassword := "SecurePass123"
	hash, err := mailbox.HashPassword(rawPassword, mailbox.DefaultArgon2Params)
	if err != nil {
		t.Fatalf("failed to hash test password: %v", err)
	}

	repo.hashes["ajar@example.com"] = hash
	repo.users["ajar@example.com"] = &dovecot.UserInfo{
		Username:           "ajar@example.com",
		Email:              "ajar@example.com",
		Domain:             "example.com",
		Status:             "active",
		ProvisioningStatus: "ready",
		UID:                5000,
		GID:                5000,
		Home:               "/var/vmail/example.com/ajar/Maildir",
	}

	t.Run("active + ready + correct PW -> PASS", func(t *testing.T) {
		err := svc.Authenticate(ctx, "ajar@example.com", "SecurePass123")
		if err != nil {
			t.Errorf("expected authentication to succeed, got %v", err)
		}
	})

	t.Run("uppercase email -> PASS", func(t *testing.T) {
		err := svc.Authenticate(ctx, "AJAR@EXAMPLE.COM", "SecurePass123")
		if err != nil {
			t.Errorf("expected case-insensitive username to succeed, got %v", err)
		}
	})

	t.Run("active + ready + wrong PW -> FAIL", func(t *testing.T) {
		err := svc.Authenticate(ctx, "ajar@example.com", "WrongPassword")
		if err != dovecot.ErrAuthenticationFailed {
			t.Errorf("expected ErrAuthenticationFailed, got %v", err)
		}
	})

	t.Run("unknown user -> FAIL (generic error)", func(t *testing.T) {
		err := svc.Authenticate(ctx, "ghost@example.com", "SecurePass123")
		if err != dovecot.ErrAuthenticationFailed {
			t.Errorf("expected ErrAuthenticationFailed for unknown user, got %v", err)
		}
	})

	t.Run("Userdb GetUserInfo returns expected derived path", func(t *testing.T) {
		info, err := svc.GetUserInfo(ctx, "ajar@example.com", "/var/vmail", 5000, 5000)
		if err != nil {
			t.Fatalf("GetUserInfo failed: %v", err)
		}
		if info.Home != "/var/vmail/example.com/ajar/Maildir" {
			t.Errorf("expected home /var/vmail/example.com/ajar/Maildir, got %s", info.Home)
		}
		if info.UID != 5000 || info.GID != 5000 {
			t.Errorf("expected UID/GID 5000, got %d/%d", info.UID, info.GID)
		}
	})
}
