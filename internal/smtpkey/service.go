package smtpkey

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/azdharsyahputra/openmail/internal/domain"
	"github.com/azdharsyahputra/openmail/internal/mailbox"
	"github.com/google/uuid"
)

var keyNameRegex = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$`)

type Service interface {
	List(ctx context.Context, domainName string) ([]*Key, error)
	Create(ctx context.Context, domainName, name string) (*IssuedKey, error)
	Revoke(ctx context.Context, domainName string, keyID uuid.UUID) error
}

type service struct {
	repo       Repository
	domainRepo domain.Service
}

func NewService(repo Repository, domainRepo domain.Service) Service {
	return &service{repo: repo, domainRepo: domainRepo}
}

func (s *service) List(ctx context.Context, domainName string) ([]*Key, error) {
	dom, err := s.getDomain(ctx, domainName)
	if err != nil {
		return nil, err
	}
	return s.repo.ListByDomain(ctx, dom.ID)
}

func (s *service) Create(ctx context.Context, domainName, name string) (*IssuedKey, error) {
	dom, err := s.getDomain(ctx, domainName)
	if err != nil {
		return nil, err
	}
	if dom.Status != "active" {
		return nil, domain.ErrDomainNotFound
	}

	name = strings.TrimSpace(name)
	if name == "" {
		name = "go-otp"
	}
	if !keyNameRegex.MatchString(name) {
		return nil, ErrInvalidName
	}

	secret, err := generateSecret()
	if err != nil {
		return nil, fmt.Errorf("generate smtp key secret: %w", err)
	}
	secretHash, err := mailbox.HashPassword(secret, mailbox.DefaultArgon2Params)
	if err != nil {
		return nil, fmt.Errorf("hash smtp key secret: %w", err)
	}

	now := time.Now().UTC()
	key := &Key{
		ID:        uuid.New(),
		DomainID:  dom.ID,
		Domain:    dom.Name,
		Name:      name,
		Username:  "mo_smtp_" + strings.ReplaceAll(uuid.NewString(), "-", ""),
		Status:    "active",
		CreatedAt: now,
	}
	if err := s.repo.Create(ctx, key, secretHash); err != nil {
		return nil, err
	}

	return &IssuedKey{Key: key, Secret: secret}, nil
}

func (s *service) Revoke(ctx context.Context, domainName string, keyID uuid.UUID) error {
	dom, err := s.getDomain(ctx, domainName)
	if err != nil {
		return err
	}
	return s.repo.Revoke(ctx, dom.ID, keyID)
}

func (s *service) getDomain(ctx context.Context, domainName string) (*domain.Domain, error) {
	return s.domainRepo.GetByName(ctx, strings.TrimSpace(strings.ToLower(domainName)))
}

func generateSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "mo_sk_" + base64.RawURLEncoding.EncodeToString(b), nil
}
