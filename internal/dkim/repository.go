package dkim

import (
	"context"

	"github.com/google/uuid"
)

type Repository interface {
	CreateDKIMKey(ctx context.Context, key *DKIMKey) error
	GetDKIMKeyByID(ctx context.Context, id uuid.UUID) (*DKIMKey, error)
	GetDKIMKeyBySelector(ctx context.Context, domainID uuid.UUID, selector string) (*DKIMKey, error)
	GetActiveDKIMKey(ctx context.Context, domainID uuid.UUID) (*DKIMKey, error)
	ListDKIMKeysByDomain(ctx context.Context, domainID uuid.UUID) ([]*DKIMKey, error)
	ActivateDKIMKey(ctx context.Context, id uuid.UUID) error
	RevokeDKIMKey(ctx context.Context, id uuid.UUID) error

	GetPolicy(ctx context.Context, domainID uuid.UUID) (*DomainMailPolicy, error)
	UpsertPolicy(ctx context.Context, policy *DomainMailPolicy) error
}
