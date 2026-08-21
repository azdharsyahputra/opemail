package identity

import (
	"strings"
	"time"
)

type IdentityStatus string

const (
	StatusActive    IdentityStatus = "active"
	StatusSuspended IdentityStatus = "suspended"
	StatusDisabled  IdentityStatus = "disabled"
	StatusPending   IdentityStatus = "pending"
	StatusDeleting  IdentityStatus = "deleting"
)

type Role string

const (
	RoleAdmin    Role = "admin"
	RoleOperator Role = "operator"
	RoleAuditor  Role = "auditor"
	RoleUser     Role = "user"
)

type Identity struct {
	ID          string            `json:"id"`
	Username    string            `json:"username"`
	Email       string            `json:"email"`
	DisplayName string            `json:"display_name,omitempty"`
	FirstName   string            `json:"first_name,omitempty"`
	LastName    string            `json:"last_name,omitempty"`
	Status      IdentityStatus    `json:"status"`
	Provider    string            `json:"provider"` // "local" or "ldap"
	Attributes  map[string]string `json:"attributes,omitempty"`
	Groups      []string          `json:"groups,omitempty"`
	Roles       []Role            `json:"roles,omitempty"`
	CreatedAt   time.Time         `json:"created_at,omitempty"`
	UpdatedAt   time.Time         `json:"updated_at,omitempty"`
}

type Group struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	DN          string   `json:"dn,omitempty"`
	Description string   `json:"description,omitempty"`
	Members     []string `json:"members,omitempty"`
}

func CanonicalizeUsername(input string) string {
	return strings.TrimSpace(strings.ToLower(input))
}
