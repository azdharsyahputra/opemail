package mailbox

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type Repository interface {
	Create(ctx context.Context, m *Mailbox) error
	GetByEmail(ctx context.Context, email string) (*Mailbox, error)
	GetByID(ctx context.Context, id uuid.UUID) (*Mailbox, error)
	List(ctx context.Context) ([]*Mailbox, error)
	UpdateProvisioningStatus(ctx context.Context, id uuid.UUID, status string) error
	UpdateStatus(ctx context.Context, id uuid.UUID, status string) error
	UpdateIdentityProvider(ctx context.Context, id uuid.UUID, provider string) error
	UpdatePasswordHash(ctx context.Context, id uuid.UUID, hash string) error

	UpdateUsedBytes(ctx context.Context, id uuid.UUID, usedBytes int64) error
	Delete(ctx context.Context, email string) error
}


type postgresRepository struct {
	db *sql.DB
}

func NewPostgresRepository(db *sql.DB) Repository {
	return &postgresRepository{db: db}
}

func (r *postgresRepository) Create(ctx context.Context, m *Mailbox) error {
	query := `
		INSERT INTO mailboxes (id, domain_id, email, password_hash, quota_bytes, used_bytes, status, provisioning_status, identity_provider, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`
	if m.ID == uuid.Nil {
		m.ID = uuid.New()
	}
	now := time.Now().UTC()
	if m.CreatedAt.IsZero() {
		m.CreatedAt = now
	}
	if m.UpdatedAt.IsZero() {
		m.UpdatedAt = now
	}
	if m.Status == "" {
		m.Status = "active"
	}
	if m.ProvisioningStatus == "" {
		m.ProvisioningStatus = ProvisioningPending
	}
	if m.IdentityProvider == "" {
		m.IdentityProvider = "local"
	}

	_, err := r.db.ExecContext(ctx, query, m.ID, m.DomainID, m.Email, m.PasswordHash, m.QuotaBytes, m.UsedBytes, m.Status, m.ProvisioningStatus, m.IdentityProvider, m.CreatedAt, m.UpdatedAt)
	if err != nil {
		return fmt.Errorf("repository create mailbox: %w", err)
	}
	return nil
}

func (r *postgresRepository) GetByEmail(ctx context.Context, email string) (*Mailbox, error) {
	query := `
		SELECT m.id, m.domain_id, m.email, m.password_hash, m.quota_bytes, COALESCE(m.used_bytes, 0), m.status, m.provisioning_status, COALESCE(m.identity_provider, 'local'), m.created_at, m.updated_at, d.name
		FROM mailboxes m
		JOIN domains d ON m.domain_id = d.id
		WHERE m.email = $1
	`
	m := &Mailbox{}
	err := r.db.QueryRowContext(ctx, query, email).Scan(
		&m.ID, &m.DomainID, &m.Email, &m.PasswordHash, &m.QuotaBytes, &m.UsedBytes, &m.Status, &m.ProvisioningStatus, &m.IdentityProvider, &m.CreatedAt, &m.UpdatedAt, &m.DomainName,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrMailboxNotFound
		}
		return nil, fmt.Errorf("repository get mailbox by email: %w", err)
	}
	return m, nil
}

func (r *postgresRepository) GetByID(ctx context.Context, id uuid.UUID) (*Mailbox, error) {
	query := `
		SELECT m.id, m.domain_id, m.email, m.password_hash, m.quota_bytes, COALESCE(m.used_bytes, 0), m.status, m.provisioning_status, COALESCE(m.identity_provider, 'local'), m.created_at, m.updated_at, d.name
		FROM mailboxes m
		JOIN domains d ON m.domain_id = d.id
		WHERE m.id = $1
	`
	m := &Mailbox{}
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&m.ID, &m.DomainID, &m.Email, &m.PasswordHash, &m.QuotaBytes, &m.UsedBytes, &m.Status, &m.ProvisioningStatus, &m.IdentityProvider, &m.CreatedAt, &m.UpdatedAt, &m.DomainName,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrMailboxNotFound
		}
		return nil, fmt.Errorf("repository get mailbox by id: %w", err)
	}
	return m, nil
}

func (r *postgresRepository) List(ctx context.Context) ([]*Mailbox, error) {
	query := `
		SELECT m.id, m.domain_id, m.email, m.password_hash, m.quota_bytes, COALESCE(m.used_bytes, 0), m.status, m.provisioning_status, COALESCE(m.identity_provider, 'local'), m.created_at, m.updated_at, d.name
		FROM mailboxes m
		JOIN domains d ON m.domain_id = d.id
		ORDER BY m.created_at ASC
	`
	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("repository list mailboxes: %w", err)
	}
	defer rows.Close()

	var mailboxes []*Mailbox
	for rows.Next() {
		m := &Mailbox{}
		if err := rows.Scan(
			&m.ID, &m.DomainID, &m.Email, &m.PasswordHash, &m.QuotaBytes, &m.UsedBytes, &m.Status, &m.ProvisioningStatus, &m.IdentityProvider, &m.CreatedAt, &m.UpdatedAt, &m.DomainName,
		); err != nil {
			return nil, fmt.Errorf("repository scan mailbox: %w", err)
		}
		mailboxes = append(mailboxes, m)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return mailboxes, nil
}


func (r *postgresRepository) UpdateProvisioningStatus(ctx context.Context, id uuid.UUID, status string) error {
	query := `UPDATE mailboxes SET provisioning_status = $1, updated_at = $2 WHERE id = $3`
	res, err := r.db.ExecContext(ctx, query, status, time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("repository update provisioning status: %w", err)
	}
	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return ErrMailboxNotFound
	}
	return nil
}

func (r *postgresRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status string) error {
	query := `UPDATE mailboxes SET status = $1, updated_at = $2 WHERE id = $3`
	res, err := r.db.ExecContext(ctx, query, status, time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("repository update status: %w", err)
	}
	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return ErrMailboxNotFound
	}
	return nil
}

func (r *postgresRepository) UpdateIdentityProvider(ctx context.Context, id uuid.UUID, provider string) error {
	query := `UPDATE mailboxes SET identity_provider = $1, updated_at = $2 WHERE id = $3`
	res, err := r.db.ExecContext(ctx, query, provider, time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("repository update identity provider: %w", err)
	}
	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return ErrMailboxNotFound
	}
	return nil
}


func (r *postgresRepository) UpdatePasswordHash(ctx context.Context, id uuid.UUID, hash string) error {
	query := `UPDATE mailboxes SET password_hash = $1, updated_at = $2 WHERE id = $3`
	res, err := r.db.ExecContext(ctx, query, hash, time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("repository update password hash: %w", err)
	}
	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return ErrMailboxNotFound
	}
	return nil
}

func (r *postgresRepository) UpdateUsedBytes(ctx context.Context, id uuid.UUID, usedBytes int64) error {
	query := `UPDATE mailboxes SET used_bytes = $1, updated_at = $2 WHERE id = $3`
	res, err := r.db.ExecContext(ctx, query, usedBytes, time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("repository update used bytes: %w", err)
	}
	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return ErrMailboxNotFound
	}
	return nil
}


func (r *postgresRepository) Delete(ctx context.Context, email string) error {

	query := `DELETE FROM mailboxes WHERE email = $1`
	res, err := r.db.ExecContext(ctx, query, email)
	if err != nil {
		return fmt.Errorf("repository delete mailbox: %w", err)
	}
	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return ErrMailboxNotFound
	}
	return nil
}
