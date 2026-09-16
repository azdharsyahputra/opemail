package smtpkey

import (
	"time"

	"github.com/google/uuid"
)

var (
	ErrKeyNotFound = errorString("smtp key not found")
	ErrKeyExists   = errorString("smtp key already exists")
	ErrInvalidName = errorString("smtp key name must be 1-64 characters and contain only letters, numbers, spaces, '.', '_' or '-'")
)

type errorString string

func (e errorString) Error() string { return string(e) }

// Key contains only metadata. The raw secret is deliberately never part of
// this type so list/get responses cannot accidentally expose it.
type Key struct {
	ID         uuid.UUID  `json:"id"`
	DomainID   uuid.UUID  `json:"domain_id"`
	Domain     string     `json:"domain"`
	Name       string     `json:"name"`
	Username   string     `json:"username"`
	Status     string     `json:"status"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

type IssuedKey struct {
	Key    *Key   `json:"key"`
	Secret string `json:"secret"`
}
