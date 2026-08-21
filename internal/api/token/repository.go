package token

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type APIToken struct {
	ID         uuid.UUID
	UserID     *uuid.UUID
	Email      string
	Role       string
	TokenHash  string
	TokenType  string
	ExpiresAt  time.Time
	RevokedAt  *time.Time
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

type Repository interface {
	Store(ctx context.Context, tok *APIToken) error
	GetByHash(ctx context.Context, tokenHash string) (*APIToken, error)
	RevokeByHash(ctx context.Context, tokenHash string) error
	RevokeAllForEmail(ctx context.Context, email string) error
	UpdateLastUsed(ctx context.Context, id uuid.UUID) error
}

type postgresRepository struct {
	db *sql.DB
}

func NewPostgresRepository(db *sql.DB) Repository {
	return &postgresRepository{db: db}
}

func (r *postgresRepository) Store(ctx context.Context, tok *APIToken) error {
	query := `
		INSERT INTO api_tokens (id, user_id, email, role, token_hash, token_type, expires_at, revoked_at, created_at, last_used_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`
	if tok.ID == uuid.Nil {
		tok.ID = uuid.New()
	}
	if tok.CreatedAt.IsZero() {
		tok.CreatedAt = time.Now().UTC()
	}

	_, err := r.db.ExecContext(ctx, query,
		tok.ID,
		tok.UserID,
		tok.Email,
		tok.Role,
		tok.TokenHash,
		tok.TokenType,
		tok.ExpiresAt,
		tok.RevokedAt,
		tok.CreatedAt,
		tok.LastUsedAt,
	)
	if err != nil {
		return fmt.Errorf("insert api_token failed: %w", err)
	}
	return nil
}

func (r *postgresRepository) GetByHash(ctx context.Context, tokenHash string) (*APIToken, error) {
	query := `
		SELECT id, user_id, email, role, token_hash, token_type, expires_at, revoked_at, created_at, last_used_at
		FROM api_tokens
		WHERE token_hash = $1
	`
	tok := &APIToken{}
	err := r.db.QueryRowContext(ctx, query, tokenHash).Scan(
		&tok.ID,
		&tok.UserID,
		&tok.Email,
		&tok.Role,
		&tok.TokenHash,
		&tok.TokenType,
		&tok.ExpiresAt,
		&tok.RevokedAt,
		&tok.CreatedAt,
		&tok.LastUsedAt,
	)
	if err != nil {
		return nil, err
	}
	return tok, nil
}

func (r *postgresRepository) RevokeByHash(ctx context.Context, tokenHash string) error {
	query := `UPDATE api_tokens SET revoked_at = NOW() WHERE token_hash = $1`
	_, err := r.db.ExecContext(ctx, query, tokenHash)
	return err
}

func (r *postgresRepository) RevokeAllForEmail(ctx context.Context, email string) error {
	query := `UPDATE api_tokens SET revoked_at = NOW() WHERE email = $1 AND revoked_at IS NULL`
	_, err := r.db.ExecContext(ctx, query, email)
	return err
}

func (r *postgresRepository) UpdateLastUsed(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE api_tokens SET last_used_at = NOW() WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
}
