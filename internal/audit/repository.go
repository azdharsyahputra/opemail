package audit

import (
	"context"

	"github.com/google/uuid"
)

type Repository interface {
	CreateMessageEvent(ctx context.Context, event *MessageEvent) error
	ListMessageEventsByMessageID(ctx context.Context, messageID uuid.UUID) ([]MessageEvent, error)
	ListMessageEventsByQueueID(ctx context.Context, queueID string) ([]MessageEvent, error)

	CreateAuditLog(ctx context.Context, log *AuditLog) error
	ListAuditLogs(ctx context.Context, limit int) ([]AuditLog, error)
}
