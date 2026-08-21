package mailbox

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrMailboxNotFound = errors.New("mailbox not found")
	ErrMailboxExists   = errors.New("mailbox already exists")
	ErrInvalidEmail    = errors.New("invalid email address format")
	ErrInvalidPassword = errors.New("password must be at least 8 characters long")
	ErrDomainNotFound  = errors.New("domain for mailbox not found")
)

type Mailbox struct {
	ID           uuid.UUID `json:"id"`
	DomainID     uuid.UUID `json:"domain_id"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
	QuotaBytes   int64     `json:"quota_bytes"`
	Status       string    `json:"status"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`

	// Helper field for display in list / CLI
	DomainName string `json:"domain_name,omitempty"`
}
