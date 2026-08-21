package dkim

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

type PostgresRepository struct {
	db *sql.DB
}

func NewPostgresRepository(db *sql.DB) *PostgresRepository {
	return &PostgresRepository{db: db}
}

func (r *PostgresRepository) CreateDKIMKey(ctx context.Context, key *DKIMKey) error {
	query := `
		INSERT INTO domain_dkim (
			id, domain_id, selector, algorithm, key_bits, status, created_at, activated_at, revoked_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);
	`
	_, err := r.db.ExecContext(ctx, query,
		key.ID,
		key.DomainID,
		strings.ToLower(key.Selector),
		key.Algorithm,
		key.KeyBits,
		string(key.Status),
		key.CreatedAt,
		key.ActivatedAt,
		key.RevokedAt,
	)
	if err != nil {
		if strings.Contains(err.Error(), "domain_dkim_selector_unique") || strings.Contains(err.Error(), "duplicate key") {
			return ErrDKIMKeyExists
		}
		return fmt.Errorf("create dkim key: %w", err)
	}
	return nil
}

func (r *PostgresRepository) GetDKIMKeyByID(ctx context.Context, id uuid.UUID) (*DKIMKey, error) {
	query := `
		SELECT k.id, k.domain_id, d.name, k.selector, k.algorithm, k.key_bits, k.status, k.created_at, k.activated_at, k.revoked_at
		FROM domain_dkim k
		JOIN domains d ON d.id = k.domain_id
		WHERE k.id = $1;
	`
	var k DKIMKey
	var statusStr string
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&k.ID,
		&k.DomainID,
		&k.Domain,
		&k.Selector,
		&k.Algorithm,
		&k.KeyBits,
		&statusStr,
		&k.CreatedAt,
		&k.ActivatedAt,
		&k.RevokedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrDKIMKeyNotFound
		}
		return nil, fmt.Errorf("get dkim key by id: %w", err)
	}
	k.Status = DKIMStatus(statusStr)
	return &k, nil
}

func (r *PostgresRepository) GetDKIMKeyBySelector(ctx context.Context, domainID uuid.UUID, selector string) (*DKIMKey, error) {
	query := `
		SELECT k.id, k.domain_id, d.name, k.selector, k.algorithm, k.key_bits, k.status, k.created_at, k.activated_at, k.revoked_at
		FROM domain_dkim k
		JOIN domains d ON d.id = k.domain_id
		WHERE k.domain_id = $1 AND LOWER(k.selector) = LOWER($2);
	`
	var k DKIMKey
	var statusStr string
	err := r.db.QueryRowContext(ctx, query, domainID, selector).Scan(
		&k.ID,
		&k.DomainID,
		&k.Domain,
		&k.Selector,
		&k.Algorithm,
		&k.KeyBits,
		&statusStr,
		&k.CreatedAt,
		&k.ActivatedAt,
		&k.RevokedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrDKIMKeyNotFound
		}
		return nil, fmt.Errorf("get dkim key by selector: %w", err)
	}
	k.Status = DKIMStatus(statusStr)
	return &k, nil
}

func (r *PostgresRepository) GetActiveDKIMKey(ctx context.Context, domainID uuid.UUID) (*DKIMKey, error) {
	query := `
		SELECT k.id, k.domain_id, d.name, k.selector, k.algorithm, k.key_bits, k.status, k.created_at, k.activated_at, k.revoked_at
		FROM domain_dkim k
		JOIN domains d ON d.id = k.domain_id
		WHERE k.domain_id = $1 AND k.status = 'active'
		ORDER BY k.activated_at DESC NULLS LAST
		LIMIT 1;
	`
	var k DKIMKey
	var statusStr string
	err := r.db.QueryRowContext(ctx, query, domainID).Scan(
		&k.ID,
		&k.DomainID,
		&k.Domain,
		&k.Selector,
		&k.Algorithm,
		&k.KeyBits,
		&statusStr,
		&k.CreatedAt,
		&k.ActivatedAt,
		&k.RevokedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrDKIMKeyNotFound
		}
		return nil, fmt.Errorf("get active dkim key: %w", err)
	}
	k.Status = DKIMStatus(statusStr)
	return &k, nil
}

func (r *PostgresRepository) ListDKIMKeysByDomain(ctx context.Context, domainID uuid.UUID) ([]*DKIMKey, error) {
	query := `
		SELECT k.id, k.domain_id, d.name, k.selector, k.algorithm, k.key_bits, k.status, k.created_at, k.activated_at, k.revoked_at
		FROM domain_dkim k
		JOIN domains d ON d.id = k.domain_id
		WHERE k.domain_id = $1
		ORDER BY k.created_at DESC;
	`
	rows, err := r.db.QueryContext(ctx, query, domainID)
	if err != nil {
		return nil, fmt.Errorf("list dkim keys: %w", err)
	}
	defer rows.Close()

	var keys []*DKIMKey
	for rows.Next() {
		var k DKIMKey
		var statusStr string
		err := rows.Scan(
			&k.ID,
			&k.DomainID,
			&k.Domain,
			&k.Selector,
			&k.Algorithm,
			&k.KeyBits,
			&statusStr,
			&k.CreatedAt,
			&k.ActivatedAt,
			&k.RevokedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan dkim key: %w", err)
		}
		k.Status = DKIMStatus(statusStr)
		keys = append(keys, &k)
	}
	return keys, rows.Err()
}

func (r *PostgresRepository) ActivateDKIMKey(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE domain_dkim
		SET status = 'active', activated_at = NOW()
		WHERE id = $1;
	`
	res, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("activate dkim key: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrDKIMKeyNotFound
	}
	return nil
}

func (r *PostgresRepository) RevokeDKIMKey(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE domain_dkim
		SET status = 'revoked', revoked_at = NOW()
		WHERE id = $1;
	`
	res, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("revoke dkim key: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrDKIMKeyNotFound
	}
	return nil
}

func (r *PostgresRepository) GetPolicy(ctx context.Context, domainID uuid.UUID) (*DomainMailPolicy, error) {
	query := `
		SELECT p.domain_id, d.name, p.spf_policy, p.dmarc_policy,
		       p.spam_threshold, p.reject_threshold, p.quarantine_enabled, p.max_message_size,
		       p.rbl_policy, p.rdns_policy, p.created_at, p.updated_at
		FROM domain_mail_policy p
		JOIN domains d ON d.id = p.domain_id
		WHERE p.domain_id = $1;
	`
	var p DomainMailPolicy
	err := r.db.QueryRowContext(ctx, query, domainID).Scan(
		&p.DomainID,
		&p.Domain,
		&p.SPFPolicy,
		&p.DMARCPolicy,
		&p.SpamThreshold,
		&p.RejectThreshold,
		&p.QuarantineEnabled,
		&p.MaxMessageSize,
		&p.RBLPolicy,
		&p.RDNSPolicy,
		&p.CreatedAt,
		&p.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrPolicyNotFound
		}
		return nil, fmt.Errorf("get domain mail policy: %w", err)
	}
	return &p, nil
}

func (r *PostgresRepository) UpsertPolicy(ctx context.Context, policy *DomainMailPolicy) error {
	query := `
		INSERT INTO domain_mail_policy (
			domain_id, spf_policy, dmarc_policy, spam_threshold, reject_threshold,
			quarantine_enabled, max_message_size, rbl_policy, rdns_policy, created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())
		ON CONFLICT (domain_id) DO UPDATE
		SET spf_policy = EXCLUDED.spf_policy,
		    dmarc_policy = EXCLUDED.dmarc_policy,
		    spam_threshold = EXCLUDED.spam_threshold,
		    reject_threshold = EXCLUDED.reject_threshold,
		    quarantine_enabled = EXCLUDED.quarantine_enabled,
		    max_message_size = EXCLUDED.max_message_size,
		    rbl_policy = EXCLUDED.rbl_policy,
		    rdns_policy = EXCLUDED.rdns_policy,
		    updated_at = NOW();
	`
	_, err := r.db.ExecContext(ctx, query,
		policy.DomainID,
		policy.SPFPolicy,
		policy.DMARCPolicy,
		policy.SpamThreshold,
		policy.RejectThreshold,
		policy.QuarantineEnabled,
		policy.MaxMessageSize,
		policy.RBLPolicy,
		policy.RDNSPolicy,
	)
	if err != nil {
		return fmt.Errorf("upsert domain mail policy: %w", err)
	}
	return nil
}

