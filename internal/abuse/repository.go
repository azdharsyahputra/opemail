package abuse

import (
	"context"

	"github.com/google/uuid"
)

type Repository interface {
	GetLimits(ctx context.Context, mailboxID uuid.UUID) (*MailboxLimits, error)
	UpsertLimits(ctx context.Context, limits *MailboxLimits) error
}
