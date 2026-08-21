package postfix

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// SenderAuthorizer validates whether an authenticated mailbox is authorized to send as a given envelope sender address.
type SenderAuthorizer interface {
	CanSendAs(ctx context.Context, authenticatedUser, sender string) (bool, error)
}

type postgresSenderAuthorizer struct {
	db *sql.DB
}

func NewPostgresSenderAuthorizer(db *sql.DB) SenderAuthorizer {
	return &postgresSenderAuthorizer{db: db}
}

func (a *postgresSenderAuthorizer) CanSendAs(ctx context.Context, authenticatedUser, sender string) (bool, error) {
	authenticatedUser = strings.TrimSpace(strings.ToLower(authenticatedUser))
	sender = strings.TrimSpace(strings.ToLower(sender))

	if authenticatedUser == "" || sender == "" {
		return false, nil
	}

	// 1. Direct match: user sending as their own primary mailbox address
	if authenticatedUser == sender {
		query := `
			SELECT 1 FROM mailboxes
			WHERE LOWER(email) = LOWER($1)
			  AND status = 'active'
			  AND provisioning_status = 'ready'
			LIMIT 1;
		`
		var dummy int
		err := a.db.QueryRowContext(ctx, query, authenticatedUser).Scan(&dummy)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return false, nil
			}
			return false, fmt.Errorf("verify primary sender: %w", err)
		}
		return true, nil
	}

	// 2. Alias match: user sending as an authorized alias targeting their mailbox
	query := `
		SELECT 1 FROM aliases a
		JOIN mailboxes m ON LOWER(a.destination) = LOWER(m.email)
		WHERE LOWER(a.source) = LOWER($1)
		  AND LOWER(m.email) = LOWER($2)
		  AND m.status = 'active'
		  AND m.provisioning_status = 'ready'
		LIMIT 1;
	`
	var dummy int
	err := a.db.QueryRowContext(ctx, query, sender, authenticatedUser).Scan(&dummy)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("verify alias sender: %w", err)
	}
	return true, nil
}
