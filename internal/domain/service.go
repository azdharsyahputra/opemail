package domain

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

var domainRegex = regexp.MustCompile(`^(?i)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

type Service interface {
	Create(ctx context.Context, name string) (*Domain, error)
	GetByName(ctx context.Context, name string) (*Domain, error)
	List(ctx context.Context) ([]*Domain, error)
	Delete(ctx context.Context, name string) error
}

type service struct {
	repo Repository
}

func NewService(repo Repository) Service {
	return &service{repo: repo}
}

func (s *service) Create(ctx context.Context, name string) (*Domain, error) {
	name = strings.TrimSpace(strings.ToLower(name))
	if !isValidDomainName(name) {
		return nil, ErrInvalidDomain
	}

	existing, err := s.repo.GetByName(ctx, name)
	if err == nil && existing != nil {
		return nil, ErrDomainExists
	}
	if err != nil && !errors.Is(err, ErrDomainNotFound) {
		return nil, err
	}

	now := time.Now().UTC()
	d := &Domain{
		ID:        uuid.New(),
		Name:      name,
		Status:    "active",
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := s.repo.Create(ctx, d); err != nil {
		return nil, err
	}

	return d, nil
}

func (s *service) GetByName(ctx context.Context, name string) (*Domain, error) {
	name = strings.TrimSpace(strings.ToLower(name))
	if name == "" {
		return nil, ErrInvalidDomain
	}
	return s.repo.GetByName(ctx, name)
}

func (s *service) List(ctx context.Context) ([]*Domain, error) {
	return s.repo.List(ctx)
}

func (s *service) Delete(ctx context.Context, name string) error {
	name = strings.TrimSpace(strings.ToLower(name))
	if name == "" {
		return ErrInvalidDomain
	}
	return s.repo.Delete(ctx, name)
}

func isValidDomainName(name string) bool {
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	return domainRegex.MatchString(name)
}
