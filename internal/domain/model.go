package domain

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrDomainNotFound = errors.New("domain not found")
	ErrDomainExists   = errors.New("domain already exists")
	ErrInvalidDomain = errors.New("invalid domain format")
)

type Domain struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
