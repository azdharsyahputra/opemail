package dovecot

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

type postgresRepository struct {
	db *sql.DB
}

func NewPostgresRepository(db *sql.DB) Repository {
	return &postgresRepository{db: db}
}

func (r *postgresRepository) GetPasswordHash(ctx context.Context, username string) (string, error) {
	username = strings.TrimSpace(strings.ToLower(username))
	query := `
		SELECT password_hash
		FROM mailboxes
		WHERE LOWER(email) = LOWER($1)
		  AND status = 'active'
		  AND provisioning_status = 'ready'
		LIMIT 1;
	`
	var hash string
	err := r.db.QueryRowContext(ctx, query, username).Scan(&hash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrUserNotFound
		}
		return "", fmt.Errorf("dovecot passdb lookup: %w", err)
	}
	return hash, nil
}

func (r *postgresRepository) GetUserInfo(ctx context.Context, username string, vmailRoot string, uid, gid int) (*UserInfo, error) {
	username = strings.TrimSpace(strings.ToLower(username))
	query := `
		SELECT m.email, d.name, m.status, m.provisioning_status
		FROM mailboxes m
		JOIN domains d ON d.id = m.domain_id
		WHERE LOWER(m.email) = LOWER($1)
		  AND m.status = 'active'
		  AND m.provisioning_status = 'ready'
		LIMIT 1;
	`
	var email, domainName, status, provStatus string
	err := r.db.QueryRowContext(ctx, query, username).Scan(&email, &domainName, &status, &provStatus)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("dovecot userdb lookup: %w", err)
	}

	parts := strings.Split(email, "@")
	localpart := parts[0]
	home := filepath.Join(vmailRoot, domainName, localpart, "Maildir")

	return &UserInfo{
		Username:           email,
		Email:              email,
		Domain:             domainName,
		Status:             status,
		ProvisioningStatus: provStatus,
		UID:                uid,
		GID:                gid,
		Home:               home,
	}, nil
}
