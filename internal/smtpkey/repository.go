package smtpkey

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

type Repository interface {
	Create(ctx context.Context, key *Key, secretHash string) error
	ListByDomain(ctx context.Context, domainID uuid.UUID) ([]*Key, error)
	Revoke(ctx context.Context, domainID, keyID uuid.UUID) error
}

type postgresRepository struct {
	db *sql.DB
}

func NewPostgresRepository(db *sql.DB) Repository {
	return &postgresRepository{db: db}
}

func (r *postgresRepository) Create(ctx context.Context, key *Key, secretHash string) error {
	const query = `
		INSERT INTO smtp_credentials (id, domain_id, name, username, secret_hash, status, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`

	_, err := r.db.ExecContext(ctx, query,
		key.ID,
		key.DomainID,
		key.Name,
		key.Username,
		secretHash,
		key.Status,
		key.CreatedAt,
	)
	if err != nil {
		if strings.Contains(err.Error(), "smtp_credentials_domain_name_unique") || strings.Contains(err.Error(), "duplicate key") {
			return ErrKeyExists
		}
		return fmt.Errorf("create smtp key: %w", err)
	}
	return nil
}

func (r *postgresRepository) ListByDomain(ctx context.Context, domainID uuid.UUID) ([]*Key, error) {
	const query = `
		SELECT k.id, k.domain_id, d.name, k.name, k.username, k.status,
		       k.created_at, k.last_used_at, k.revoked_at
		FROM smtp_credentials k
		JOIN domains d ON d.id = k.domain_id
		WHERE k.domain_id = $1
		ORDER BY k.created_at DESC`

	rows, err := r.db.QueryContext(ctx, query, domainID)
	if err != nil {
		return nil, fmt.Errorf("list smtp keys: %w", err)
	}
	defer rows.Close()

	var keys []*Key
	for rows.Next() {
		key := &Key{}
		if err := rows.Scan(
			&key.ID,
			&key.DomainID,
			&key.Domain,
			&key.Name,
			&key.Username,
			&key.Status,
			&key.CreatedAt,
			&key.LastUsedAt,
			&key.RevokedAt,
		); err != nil {
			return nil, fmt.Errorf("scan smtp key: %w", err)
		}
		keys = append(keys, key)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate smtp keys: %w", err)
	}
	if keys == nil {
		keys = make([]*Key, 0)
	}
	return keys, nil
}

func (r *postgresRepository) Revoke(ctx context.Context, domainID, keyID uuid.UUID) error {
	const query = `
		UPDATE smtp_credentials
		SET status = 'revoked', revoked_at = COALESCE(revoked_at, $3)
		WHERE domain_id = $1 AND id = $2 AND status = 'active'`

	result, err := r.db.ExecContext(ctx, query, domainID, keyID, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("revoke smtp key: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check revoked smtp key: %w", err)
	}
	if count == 0 {
		return ErrKeyNotFound
	}
	return nil
}
