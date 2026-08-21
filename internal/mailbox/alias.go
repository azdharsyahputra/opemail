package mailbox

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	ErrAliasNotFound      = errors.New("alias not found")
	ErrAliasAlreadyExists = errors.New("alias already exists")
	ErrInvalidAlias       = errors.New("invalid alias address")
)

type Alias struct {
	ID          uuid.UUID `json:"id"`
	DomainID    uuid.UUID `json:"domain_id"`
	Source      string    `json:"source"`
	Destination string    `json:"destination"`
	CreatedAt   time.Time `json:"created_at"`
}

type AliasRepository interface {
	CreateAlias(ctx context.Context, alias *Alias) error
	GetAlias(ctx context.Context, source, destination string) (*Alias, error)
	ListAliasesByDestination(ctx context.Context, destination string) ([]*Alias, error)
	ListAllAliases(ctx context.Context) ([]*Alias, error)
	DeleteAlias(ctx context.Context, source, destination string) error
}

type aliasPostgresRepo struct {
	db *sql.DB
}

func NewAliasRepository(db *sql.DB) AliasRepository {
	return &aliasPostgresRepo{db: db}
}

func (r *aliasPostgresRepo) CreateAlias(ctx context.Context, a *Alias) error {
	if a.ID == uuid.Nil {
		a.ID = uuid.New()
	}
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now().UTC()
	}

	query := `
		INSERT INTO aliases (id, domain_id, source, destination, created_at)
		VALUES ($1, $2, $3, $4, $5)
	`
	_, err := r.db.ExecContext(ctx, query, a.ID, a.DomainID, strings.ToLower(a.Source), strings.ToLower(a.Destination), a.CreatedAt)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") || strings.Contains(err.Error(), "unique") {
			return ErrAliasAlreadyExists
		}
		return fmt.Errorf("create alias failed: %w", err)
	}
	return nil
}

func (r *aliasPostgresRepo) GetAlias(ctx context.Context, source, destination string) (*Alias, error) {
	query := `
		SELECT id, domain_id, source, destination, created_at
		FROM aliases
		WHERE source = $1 AND destination = $2
	`
	a := &Alias{}
	err := r.db.QueryRowContext(ctx, query, strings.ToLower(source), strings.ToLower(destination)).Scan(
		&a.ID,
		&a.DomainID,
		&a.Source,
		&a.Destination,
		&a.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrAliasNotFound
		}
		return nil, err
	}
	return a, nil
}

func (r *aliasPostgresRepo) ListAliasesByDestination(ctx context.Context, destination string) ([]*Alias, error) {
	query := `
		SELECT id, domain_id, source, destination, created_at
		FROM aliases
		WHERE destination = $1
		ORDER BY source ASC
	`
	rows, err := r.db.QueryContext(ctx, query, strings.ToLower(destination))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var aliases []*Alias
	for rows.Next() {
		a := &Alias{}
		if err := rows.Scan(&a.ID, &a.DomainID, &a.Source, &a.Destination, &a.CreatedAt); err != nil {
			return nil, err
		}
		aliases = append(aliases, a)
	}
	return aliases, nil
}

func (r *aliasPostgresRepo) ListAllAliases(ctx context.Context) ([]*Alias, error) {
	query := `
		SELECT id, domain_id, source, destination, created_at
		FROM aliases
		ORDER BY source ASC
	`
	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var aliases []*Alias
	for rows.Next() {
		a := &Alias{}
		if err := rows.Scan(&a.ID, &a.DomainID, &a.Source, &a.Destination, &a.CreatedAt); err != nil {
			return nil, err
		}
		aliases = append(aliases, a)
	}
	return aliases, nil
}

func (r *aliasPostgresRepo) DeleteAlias(ctx context.Context, source, destination string) error {
	query := `DELETE FROM aliases WHERE source = $1 AND destination = $2`
	res, err := r.db.ExecContext(ctx, query, strings.ToLower(source), strings.ToLower(destination))
	if err != nil {
		return err
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return ErrAliasNotFound
	}
	return nil
}
