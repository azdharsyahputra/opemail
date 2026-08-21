package mailbox_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/azdharsyahputra/openmail/internal/domain"
	"github.com/azdharsyahputra/openmail/internal/mailbox"
	"github.com/google/uuid"
)

type mockDomainRepo struct {
	mu      sync.Mutex
	domains map[string]*domain.Domain
}

func newMockDomainRepo() *mockDomainRepo {
	return &mockDomainRepo{domains: make(map[string]*domain.Domain)}
}

func (m *mockDomainRepo) Create(ctx context.Context, d *domain.Domain) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.domains[d.Name] = d
	return nil
}

func (m *mockDomainRepo) GetByName(ctx context.Context, name string) (*domain.Domain, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.domains[name]
	if !ok {
		return nil, domain.ErrDomainNotFound
	}
	return d, nil
}

func (m *mockDomainRepo) GetByID(ctx context.Context, id uuid.UUID) (*domain.Domain, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, d := range m.domains {
		if d.ID == id {
			return d, nil
		}
	}
	return nil, domain.ErrDomainNotFound
}

func (m *mockDomainRepo) List(ctx context.Context) ([]*domain.Domain, error) {
	return nil, nil
}

func (m *mockDomainRepo) Delete(ctx context.Context, name string) error {
	return nil
}

type mockMailboxRepo struct {
	mu        sync.Mutex
	mailboxes map[string]*mailbox.Mailbox
}

func newMockMailboxRepo() *mockMailboxRepo {
	return &mockMailboxRepo{mailboxes: make(map[string]*mailbox.Mailbox)}
}

func (m *mockMailboxRepo) Create(ctx context.Context, mb *mailbox.Mailbox) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.mailboxes[mb.Email]; ok {
		return mailbox.ErrMailboxExists
	}
	m.mailboxes[mb.Email] = mb
	return nil
}

func (m *mockMailboxRepo) GetByEmail(ctx context.Context, email string) (*mailbox.Mailbox, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	mb, ok := m.mailboxes[email]
	if !ok {
		return nil, mailbox.ErrMailboxNotFound
	}
	return mb, nil
}

func (m *mockMailboxRepo) GetByID(ctx context.Context, id uuid.UUID) (*mailbox.Mailbox, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, mb := range m.mailboxes {
		if mb.ID == id {
			return mb, nil
		}
	}
	return nil, mailbox.ErrMailboxNotFound
}

func (m *mockMailboxRepo) List(ctx context.Context) ([]*mailbox.Mailbox, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var list []*mailbox.Mailbox
	for _, mb := range m.mailboxes {
		list = append(list, mb)
	}
	return list, nil
}

func (m *mockMailboxRepo) Delete(ctx context.Context, email string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.mailboxes[email]; !ok {
		return mailbox.ErrMailboxNotFound
	}
	delete(m.mailboxes, email)
	return nil
}

func TestMailboxService(t *testing.T) {
	domRepo := newMockDomainRepo()
	mbRepo := newMockMailboxRepo()
	svc := mailbox.NewService(mbRepo, domRepo)
	ctx := context.Background()

	// Seed domain
	testDomain := &domain.Domain{
		ID:        uuid.New(),
		Name:      "example.com",
		Status:    "active",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	_ = domRepo.Create(ctx, testDomain)

	t.Run("Create valid mailbox", func(t *testing.T) {
		mb, err := svc.Create(ctx, "ajar@example.com", "securepass123", 1073741824)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if mb.Email != "ajar@example.com" {
			t.Errorf("expected email ajar@example.com, got %s", mb.Email)
		}
		if mb.DomainName != "example.com" {
			t.Errorf("expected domain name example.com, got %s", mb.DomainName)
		}

		// Verify Argon2id password hash
		valid, err := svc.VerifyPassword("securepass123", mb.PasswordHash)
		if err != nil || !valid {
			t.Errorf("expected password verification to succeed, valid=%v err=%v", valid, err)
		}
	})

	t.Run("Create duplicate mailbox", func(t *testing.T) {
		_, err := svc.Create(ctx, "ajar@example.com", "securepass123", 1073741824)
		if err != mailbox.ErrMailboxExists {
			t.Errorf("expected ErrMailboxExists, got %v", err)
		}
	})

	t.Run("Create mailbox with nonexistent domain", func(t *testing.T) {
		_, err := svc.Create(ctx, "user@unknown.com", "securepass123", 1073741824)
		if err != mailbox.ErrDomainNotFound {
			t.Errorf("expected ErrDomainNotFound, got %v", err)
		}
	})

	t.Run("Create mailbox with invalid email", func(t *testing.T) {
		invalidEmails := []string{"invalid-email", "@example.com", "user@", ""}
		for _, email := range invalidEmails {
			_, err := svc.Create(ctx, email, "securepass123", 1073741824)
			if err != mailbox.ErrInvalidEmail {
				t.Errorf("expected ErrInvalidEmail for %q, got %v", email, err)
			}
		}
	})

	t.Run("Create mailbox with weak password", func(t *testing.T) {
		_, err := svc.Create(ctx, "shortpass@example.com", "short", 1073741824)
		if err != mailbox.ErrInvalidPassword {
			t.Errorf("expected ErrInvalidPassword, got %v", err)
		}
	})

	t.Run("Get mailbox by email", func(t *testing.T) {
		mb, err := svc.GetByEmail(ctx, "ajar@example.com")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if mb.Email != "ajar@example.com" {
			t.Errorf("expected email ajar@example.com, got %s", mb.Email)
		}
	})

	t.Run("List mailboxes", func(t *testing.T) {
		list, err := svc.List(ctx)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if len(list) != 1 {
			t.Errorf("expected 1 mailbox, got %d", len(list))
		}
	})

	t.Run("Delete mailbox", func(t *testing.T) {
		err := svc.Delete(ctx, "ajar@example.com")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		_, err = svc.GetByEmail(ctx, "ajar@example.com")
		if err != mailbox.ErrMailboxNotFound {
			t.Errorf("expected ErrMailboxNotFound after deletion, got %v", err)
		}
	})

	t.Run("Delete nonexistent mailbox", func(t *testing.T) {
		err := svc.Delete(ctx, "nonexistent@example.com")
		if err != mailbox.ErrMailboxNotFound {
			t.Errorf("expected ErrMailboxNotFound, got %v", err)
		}
	})
}
