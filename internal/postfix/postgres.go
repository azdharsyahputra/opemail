package postfix

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

type postgresRepository struct {
	db *sql.DB
}

func NewPostgresRepository(db *sql.DB) Repository {
	return &postgresRepository{db: db}
}

func (r *postgresRepository) LookupVirtualDomain(ctx context.Context, domainName string) (bool, error) {
	domainName = strings.TrimSpace(strings.ToLower(domainName))
	query := `
		SELECT 1
		FROM domains
		WHERE LOWER(name) = LOWER($1)
		  AND status = 'active'
		LIMIT 1
	`
	var val int
	err := r.db.QueryRowContext(ctx, query, domainName).Scan(&val)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("postfix domain lookup: %w", err)
	}
	return true, nil
}

func (r *postgresRepository) LookupVirtualMailbox(ctx context.Context, email string) (bool, error) {
	email = strings.TrimSpace(strings.ToLower(email))
	query := `
		SELECT 1
		FROM mailboxes m
		JOIN domains d ON d.id = m.domain_id
		WHERE LOWER(m.email) = LOWER($1)
		  AND m.status = 'active'
		  AND m.provisioning_status = 'ready'
		LIMIT 1
	`
	var val int
	err := r.db.QueryRowContext(ctx, query, email).Scan(&val)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("postfix mailbox lookup: %w", err)
	}
	return true, nil
}

func (r *postgresRepository) LookupVirtualAlias(ctx context.Context, sourceEmail string) ([]string, error) {
	sourceEmail = strings.TrimSpace(strings.ToLower(sourceEmail))
	query := `
		SELECT a.destination
		FROM aliases a
		JOIN domains d ON d.id = a.domain_id
		WHERE LOWER(a.source) = LOWER($1)
		  AND d.status = 'active'
	`
	rows, err := r.db.QueryContext(ctx, query, sourceEmail)
	if err != nil {
		return nil, fmt.Errorf("postfix alias lookup: %w", err)
	}
	defer rows.Close()

	var destinations []string
	for rows.Next() {
		var dest string
		if err := rows.Scan(&dest); err != nil {
			return nil, fmt.Errorf("scan alias destination: %w", err)
		}
		destinations = append(destinations, dest)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return destinations, nil
}
