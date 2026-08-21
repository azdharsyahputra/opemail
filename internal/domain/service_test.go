package domain_test

import (
	"context"
	"sync"
	"testing"

	"github.com/azdharsyahputra/openmail/internal/domain"
	"github.com/google/uuid"
)

type mockDomainRepo struct {
	mu      sync.Mutex
	domains map[string]*domain.Domain
}

func newMockDomainRepo() *mockDomainRepo {
	return &mockDomainRepo{
		domains: make(map[string]*domain.Domain),
	}
}

func (m *mockDomainRepo) Create(ctx context.Context, d *domain.Domain) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.domains[d.Name]; exists {
		return domain.ErrDomainExists
	}
	m.domains[d.Name] = d
	return nil
}

func (m *mockDomainRepo) GetByName(ctx context.Context, name string) (*domain.Domain, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, exists := m.domains[name]
	if !exists {
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
	m.mu.Lock()
	defer m.mu.Unlock()
	var list []*domain.Domain
	for _, d := range m.domains {
		list = append(list, d)
	}
	return list, nil
}

func (m *mockDomainRepo) Delete(ctx context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.domains[name]; !exists {
		return domain.ErrDomainNotFound
	}
	delete(m.domains, name)
	return nil
}

func TestDomainService(t *testing.T) {
	repo := newMockDomainRepo()
	svc := domain.NewService(repo)
	ctx := context.Background()

	t.Run("Create valid domain", func(t *testing.T) {
		d, err := svc.Create(ctx, "example.com")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if d.Name != "example.com" {
			t.Errorf("expected domain name example.com, got %s", d.Name)
		}
	})

	t.Run("Create duplicate domain", func(t *testing.T) {
		_, err := svc.Create(ctx, "example.com")
		if err != domain.ErrDomainExists {
			t.Errorf("expected ErrDomainExists, got %v", err)
		}
	})

	t.Run("Create invalid domain", func(t *testing.T) {
		invalidDomains := []string{"invalid_domain", "", "domain.", ".com", "domain..com"}
		for _, inv := range invalidDomains {
			_, err := svc.Create(ctx, inv)
			if err != domain.ErrInvalidDomain {
				t.Errorf("expected ErrInvalidDomain for %q, got %v", inv, err)
			}
		}
	})

	t.Run("Get domain by name", func(t *testing.T) {
		d, err := svc.GetByName(ctx, "example.com")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if d.Name != "example.com" {
			t.Errorf("expected domain name example.com, got %s", d.Name)
		}
	})

	t.Run("Get nonexistent domain", func(t *testing.T) {
		_, err := svc.GetByName(ctx, "nonexistent.com")
		if err != domain.ErrDomainNotFound {
			t.Errorf("expected ErrDomainNotFound, got %v", err)
		}
	})

	t.Run("List domains", func(t *testing.T) {
		list, err := svc.List(ctx)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if len(list) != 1 {
			t.Errorf("expected 1 domain, got %d", len(list))
		}
	})

	t.Run("Delete domain", func(t *testing.T) {
		err := svc.Delete(ctx, "example.com")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		_, err = svc.GetByName(ctx, "example.com")
		if err != domain.ErrDomainNotFound {
			t.Errorf("expected ErrDomainNotFound after delete, got %v", err)
		}
	})

	t.Run("Delete nonexistent domain", func(t *testing.T) {
		err := svc.Delete(ctx, "nonexistent.com")
		if err != domain.ErrDomainNotFound {
			t.Errorf("expected ErrDomainNotFound, got %v", err)
		}
	})
}
