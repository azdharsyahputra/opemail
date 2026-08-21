package postfix_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/azdharsyahputra/openmail/internal/postfix"
)

type mockPostfixRepo struct {
	domains   map[string]bool
	mailboxes map[string]bool
	aliases   map[string][]string
}

func newMockPostfixRepo() *mockPostfixRepo {
	return &mockPostfixRepo{
		domains:   make(map[string]bool),
		mailboxes: make(map[string]bool),
		aliases:   make(map[string][]string),
	}
}

func (m *mockPostfixRepo) LookupVirtualDomain(ctx context.Context, domainName string) (bool, error) {
	return m.domains[strings.ToLower(domainName)], nil
}

func (m *mockPostfixRepo) LookupVirtualMailbox(ctx context.Context, email string) (bool, error) {
	return m.mailboxes[strings.ToLower(email)], nil
}

func (m *mockPostfixRepo) LookupVirtualAlias(ctx context.Context, sourceEmail string) ([]string, error) {
	dest, ok := m.aliases[strings.ToLower(sourceEmail)]
	if !ok {
		return nil, nil
	}
	return dest, nil
}

func TestPostfixConfigGeneration(t *testing.T) {
	opts := postfix.ConfigOptions{
		ConfigDir:  "/etc/postfix",
		Hostname:   "mail.example.com",
		VmailRoot:  "/var/vmail",
		VmailUID:   5000,
		VmailGID:   5000,
		DBHost:     "127.0.0.1",
		DBPort:     5432,
		DBName:     "mailopen",
		DBUser:     "mailopen_postfix",
		DBPassword: "secretpassword",
	}

	configs := postfix.GenerateConfigs(opts)

	t.Run("main.cf contains virtual mailbox directives without home_mailbox", func(t *testing.T) {
		if strings.Contains(configs.MainCF, "home_mailbox") {
			t.Error("main.cf should not contain home_mailbox")
		}
		if !strings.Contains(configs.MainCF, "virtual_mailbox_domains = proxy:pgsql:") && !strings.Contains(configs.MainCF, "virtual_mailbox_domains = pgsql:") {
			t.Error("main.cf missing virtual_mailbox_domains")
		}
		if !strings.Contains(configs.MainCF, "virtual_mailbox_maps = proxy:pgsql:") && !strings.Contains(configs.MainCF, "virtual_mailbox_maps = pgsql:") {
			t.Error("main.cf missing virtual_mailbox_maps")
		}
		if !strings.Contains(configs.MainCF, "virtual_alias_maps = proxy:pgsql:") && !strings.Contains(configs.MainCF, "virtual_alias_maps = pgsql:") {
			t.Error("main.cf missing virtual_alias_maps")
		}

		if !strings.Contains(configs.MainCF, "virtual_mailbox_base = /var/vmail") {
			t.Error("main.cf missing virtual_mailbox_base")
		}
		if !strings.Contains(configs.MainCF, "virtual_uid_maps = static:5000") {
			t.Error("main.cf missing virtual_uid_maps")
		}
		if !strings.Contains(configs.MainCF, "reject_unauth_destination") {
			t.Error("main.cf missing anti-relay reject_unauth_destination")
		}
	})

	t.Run("pgsql maps contain expected queries and credentials", func(t *testing.T) {
		if !strings.Contains(configs.VirtualMailboxDomainsCF, "WHERE LOWER(name) = LOWER('%s')") {
			t.Error("domains CF missing LOWER(name) query")
		}
		if !strings.Contains(configs.VirtualMailboxMapsCF, "provisioning_status = 'ready'") {
			t.Error("mailbox CF missing provisioning_status = ready filter")
		}
		if !strings.Contains(configs.VirtualMailboxMapsCF, "Maildir/'") {
			t.Error("mailbox CF query must return Maildir/ path ending with slash")
		}
		if !strings.Contains(configs.VirtualAliasMapsCF, "SELECT a.destination FROM aliases a") {
			t.Error("alias CF missing query")
		}
		if !strings.Contains(configs.VirtualMailboxMapsCF, "user = mailopen_postfix") {
			t.Error("mailbox CF missing db user")
		}
	})


	t.Run("master.cf contains submission service with Dovecot SASL and sender restrictions", func(t *testing.T) {
		if !strings.Contains(configs.MasterCF, "submission inet") {
			t.Error("master.cf missing submission service")
		}
		if !strings.Contains(configs.MasterCF, "smtpd_sasl_auth_enable=yes") {
			t.Error("master.cf missing smtpd_sasl_auth_enable=yes")
		}
		if !strings.Contains(configs.MasterCF, "smtpd_sasl_type=dovecot") {
			t.Error("master.cf missing smtpd_sasl_type=dovecot")
		}
		if !strings.Contains(configs.MasterCF, "reject_sender_login_mismatch") {
			t.Error("master.cf missing reject_sender_login_mismatch")
		}
	})

	t.Run("pgsql-sender-login-maps.cf contains query for mailbox and aliases", func(t *testing.T) {
		if !strings.Contains(configs.SenderLoginMapsCF, "SELECT email FROM mailboxes") {
			t.Error("sender login CF missing mailbox email query")
		}
		if !strings.Contains(configs.SenderLoginMapsCF, "UNION") {
			t.Error("sender login CF missing UNION query for aliases")
		}
	})

	t.Run("WriteConfigsAtomically writes 0640 permission files", func(t *testing.T) {
		tempDir, err := os.MkdirTemp("", "openmail-postfix-test-*")
		if err != nil {
			t.Fatalf("failed to create temp dir: %v", err)
		}
		defer os.RemoveAll(tempDir)

		opts.ConfigDir = tempDir
		err = postfix.WriteConfigsAtomically(opts)
		if err != nil {
			t.Fatalf("WriteConfigsAtomically failed: %v", err)
		}

		expectedFiles := []string{
			"main.cf",
			"master.cf",
			"pgsql-virtual-mailbox-domains.cf",
			"pgsql-virtual-mailbox-maps.cf",
			"pgsql-virtual-alias-maps.cf",
			"pgsql-sender-login-maps.cf",
		}

		for _, f := range expectedFiles {
			p := filepath.Join(tempDir, f)
			info, err := os.Stat(p)
			if err != nil {
				t.Errorf("expected file %s to exist, err: %v", f, err)
				continue
			}
			if perm := info.Mode().Perm(); perm > 0640 {
				t.Errorf("file %s expected perm <= 0640, got %04o", f, perm)
			}
		}
	})
}

func TestPostfixTransportValidation(t *testing.T) {
	repo := newMockPostfixRepo()
	prov := postfix.NewSystemProvisioner("/tmp")
	svc := postfix.NewService(repo, prov)
	ctx := context.Background()

	// Seed domain & mailbox & alias
	repo.domains["example.com"] = true
	repo.mailboxes["ajar@example.com"] = true
	repo.aliases["support@example.com"] = []string{"ajar@example.com"}

	t.Run("Valid active domain and ready mailbox recipient", func(t *testing.T) {
		valid, err := svc.ValidateRecipient(ctx, "ajar@example.com")
		if err != nil || !valid {
			t.Errorf("expected valid recipient, valid=%v err=%v", valid, err)
		}
	})

	t.Run("Case-insensitive recipient validation", func(t *testing.T) {
		valid, err := svc.ValidateRecipient(ctx, "AJAR@EXAMPLE.COM")
		if err != nil || !valid {
			t.Errorf("expected valid case-insensitive recipient, valid=%v err=%v", valid, err)
		}
	})

	t.Run("Valid alias recipient", func(t *testing.T) {
		valid, err := svc.ValidateRecipient(ctx, "support@example.com")
		if err != nil || !valid {
			t.Errorf("expected valid alias recipient, valid=%v err=%v", valid, err)
		}
	})

	t.Run("Unknown domain rejected", func(t *testing.T) {
		valid, err := svc.ValidateRecipient(ctx, "user@unknowndomain.com")
		if err != postfix.ErrDomainNotFound || valid {
			t.Errorf("expected ErrDomainNotFound, got valid=%v err=%v", valid, err)
		}
	})

	t.Run("Unknown mailbox in valid domain rejected", func(t *testing.T) {
		valid, err := svc.ValidateRecipient(ctx, "ghost@example.com")
		if err != postfix.ErrMailboxNotFound || valid {
			t.Errorf("expected ErrMailboxNotFound, got valid=%v err=%v", valid, err)
		}
	})

	t.Run("Invalid email format rejected", func(t *testing.T) {
		invalidEmails := []string{"invalid", "@example.com", "user@", ""}
		for _, email := range invalidEmails {
			_, err := svc.ValidateRecipient(ctx, email)
			if err != postfix.ErrInvalidRecipient {
				t.Errorf("expected ErrInvalidRecipient for %q, got %v", email, err)
			}
		}
	})
}
