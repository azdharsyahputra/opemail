package domain

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

type Repository interface {
	Create(ctx context.Context, d *Domain) error
	GetByName(ctx context.Context, name string) (*Domain, error)
	GetByID(ctx context.Context, id uuid.UUID) (*Domain, error)
	List(ctx context.Context) ([]*Domain, error)
	Delete(ctx context.Context, name string) error
}

type postgresRepository struct {
	db *sql.DB
}

func NewPostgresRepository(db *sql.DB) Repository {
	return &postgresRepository{db: db}
}

func (r *postgresRepository) Create(ctx context.Context, d *Domain) error {
	query := `INSERT INTO domains (id, name, status, created_at, updated_at) VALUES ($1, $2, $3, $4, $5)`
	_, err := r.db.ExecContext(ctx, query, d.ID, d.Name, d.Status, d.CreatedAt, d.UpdatedAt)
	if err != nil {
		return fmt.Errorf("repository create domain: %w", err)
	}
	return nil
}

func (r *postgresRepository) GetByName(ctx context.Context, name string) (*Domain, error) {
	query := `SELECT id, name, status, created_at, updated_at FROM domains WHERE name = $1`
	d := &Domain{}
	err := r.db.QueryRowContext(ctx, query, name).Scan(&d.ID, &d.Name, &d.Status, &d.CreatedAt, &d.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrDomainNotFound
		}
		return nil, fmt.Errorf("repository get domain by name: %w", err)
	}
	return d, nil
}

func (r *postgresRepository) GetByID(ctx context.Context, id uuid.UUID) (*Domain, error) {
	query := `SELECT id, name, status, created_at, updated_at FROM domains WHERE id = $1`
	d := &Domain{}
	err := r.db.QueryRowContext(ctx, query, id).Scan(&d.ID, &d.Name, &d.Status, &d.CreatedAt, &d.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrDomainNotFound
		}
		return nil, fmt.Errorf("repository get domain by id: %w", err)
	}
	return d, nil
}

func (r *postgresRepository) List(ctx context.Context) ([]*Domain, error) {
	query := `SELECT id, name, status, created_at, updated_at FROM domains ORDER BY created_at DESC`
	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("repository list domains: %w", err)
	}
	defer rows.Close()

	var domains []*Domain
	for rows.Next() {
		d := &Domain{}
		if err := rows.Scan(&d.ID, &d.Name, &d.Status, &d.CreatedAt, &d.UpdatedAt); err != nil {
			return nil, fmt.Errorf("repository scan domain: %w", err)
		}
		domains = append(domains, d)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return domains, nil
}

func (r *postgresRepository) Delete(ctx context.Context, name string) error {
	query := `DELETE FROM domains WHERE name = $1`
	res, err := r.db.ExecContext(ctx, query, name)
	if err != nil {
		return fmt.Errorf("repository delete domain: %w", err)
	}
	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return ErrDomainNotFound
	}
	return nil
}
