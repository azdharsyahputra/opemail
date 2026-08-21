package audit

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
)

type PostgresRepository struct {
	db *sql.DB
}

func NewPostgresRepository(db *sql.DB) *PostgresRepository {
	return &PostgresRepository{db: db}
}

func (r *PostgresRepository) CreateMessageEvent(ctx context.Context, e *MessageEvent) error {
	if e.ID == uuid.Nil {
		e.ID = uuid.New()
	}
	query := `
		INSERT INTO message_events (id, message_id, queue_id, event_type, status, detail, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, NOW())
	`
	var msgID *uuid.UUID
	if e.MessageID != uuid.Nil {
		msgID = &e.MessageID
	}
	var qID *string
	if e.QueueID != "" {
		qID = &e.QueueID
	}

	_, err := r.db.ExecContext(ctx, query, e.ID, msgID, qID, string(e.EventType), e.Status, e.Detail)
	if err != nil {
		return fmt.Errorf("create message event: %w", err)
	}
	return nil
}

func (r *PostgresRepository) ListMessageEventsByMessageID(ctx context.Context, messageID uuid.UUID) ([]MessageEvent, error) {
	query := `
		SELECT id, message_id, COALESCE(queue_id, ''), event_type, status, COALESCE(detail, ''), created_at
		FROM message_events
		WHERE message_id = $1
		ORDER BY created_at ASC
	`
	rows, err := r.db.QueryContext(ctx, query, messageID)
	if err != nil {
		return nil, fmt.Errorf("list message events: %w", err)
	}
	defer rows.Close()

	var events []MessageEvent
	for rows.Next() {
		var e MessageEvent
		var mid *uuid.UUID
		if err := rows.Scan(&e.ID, &mid, &e.QueueID, &e.EventType, &e.Status, &e.Detail, &e.CreatedAt); err != nil {
			return nil, err
		}
		if mid != nil {
			e.MessageID = *mid
		}
		events = append(events, e)
	}
	return events, rows.Err()
}

func (r *PostgresRepository) ListMessageEventsByQueueID(ctx context.Context, queueID string) ([]MessageEvent, error) {
	query := `
		SELECT id, message_id, COALESCE(queue_id, ''), event_type, status, COALESCE(detail, ''), created_at
		FROM message_events
		WHERE queue_id = $1
		ORDER BY created_at ASC
	`
	rows, err := r.db.QueryContext(ctx, query, queueID)
	if err != nil {
		return nil, fmt.Errorf("list queue events: %w", err)
	}
	defer rows.Close()

	var events []MessageEvent
	for rows.Next() {
		var e MessageEvent
		var mid *uuid.UUID
		if err := rows.Scan(&e.ID, &mid, &e.QueueID, &e.EventType, &e.Status, &e.Detail, &e.CreatedAt); err != nil {
			return nil, err
		}
		if mid != nil {
			e.MessageID = *mid
		}
		events = append(events, e)
	}
	return events, rows.Err()
}

func (r *PostgresRepository) CreateAuditLog(ctx context.Context, log *AuditLog) error {
	if log.ID == uuid.Nil {
		log.ID = uuid.New()
	}
	query := `
		INSERT INTO audit_logs (id, actor_type, actor_id, action, resource_type, resource_id, metadata, ip_address, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
	`
	var ipStr *string
	if log.IPAddress != nil {
		s := log.IPAddress.String()
		ipStr = &s
	}

	_, err := r.db.ExecContext(ctx, query,
		log.ID,
		log.ActorType,
		log.ActorID,
		log.Action,
		log.ResourceType,
		log.ResourceID,
		log.Metadata,
		ipStr,
	)
	if err != nil {
		return fmt.Errorf("create audit log: %w", err)
	}
	return nil
}

func (r *PostgresRepository) ListAuditLogs(ctx context.Context, limit int) ([]AuditLog, error) {
	if limit <= 0 {
		limit = 50
	}
	query := `
		SELECT id, actor_type, actor_id, action, resource_type, resource_id, metadata, ip_address, created_at
		FROM audit_logs
		ORDER BY created_at DESC
		LIMIT $1
	`
	rows, err := r.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("list audit logs: %w", err)
	}
	defer rows.Close()

	var logs []AuditLog
	for rows.Next() {
		var l AuditLog
		var meta []byte
		var ipStr sql.NullString
		if err := rows.Scan(&l.ID, &l.ActorType, &l.ActorID, &l.Action, &l.ResourceType, &l.ResourceID, &meta, &ipStr, &l.CreatedAt); err != nil {
			return nil, err
		}
		l.Metadata = meta
		if ipStr.Valid {
			// parse IP
		}
		logs = append(logs, l)
	}
	return logs, rows.Err()
}
