package inbound

import (
	"context"
	"database/sql"
	"strings"
)

// RecipientVerifier validates whether an inbound recipient can receive emails without user enumeration leaks.
type RecipientVerifier interface {
	VerifyRecipient(ctx context.Context, email string) (bool, error)
}

type PostgresRecipientVerifier struct {
	db *sql.DB
}

func NewPostgresRecipientVerifier(db *sql.DB) *PostgresRecipientVerifier {
	return &PostgresRecipientVerifier{db: db}
}

func (v *PostgresRecipientVerifier) VerifyRecipient(ctx context.Context, email string) (bool, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false, nil
	}
	domainName := parts[1]

	// 1. Verify Domain is Active
	var domainID string
	err := v.db.QueryRowContext(ctx, "SELECT id FROM domains WHERE LOWER(name) = $1 AND status = 'active'", domainName).Scan(&domainID)
	if err != nil {
		return false, nil
	}

	// 2. Check Active & Ready Mailbox
	var mailboxCount int
	err = v.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM mailboxes WHERE LOWER(email) = $1 AND status = 'active' AND (provisioning_status = 'ready' OR provisioning_status IS NULL)",
		email,
	).Scan(&mailboxCount)
	if err == nil && mailboxCount > 0 {
		return true, nil
	}

	// 3. Check Active Alias
	var aliasCount int
	err = v.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM aliases WHERE LOWER(source) = $1 AND status = 'active'",
		email,
	).Scan(&aliasCount)
	if err == nil && aliasCount > 0 {
		return true, nil
	}

	// Any other state (unknown, suspended, deleted, pending) returns false consistently
	return false, nil
}
