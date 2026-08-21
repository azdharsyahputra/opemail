package audit

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
)

type Service interface {
	RecordMessageEvent(ctx context.Context, messageID uuid.UUID, queueID string, eventType EventType, status string, detail string) error
	ListMessageEvents(ctx context.Context, messageID uuid.UUID) ([]MessageEvent, error)
	TraceMessage(ctx context.Context, messageID uuid.UUID) (*MessageTrace, error)

	RecordAudit(ctx context.Context, actorType string, actorID *uuid.UUID, action string, resourceType string, resourceID *uuid.UUID, metadata any) error
	ListAuditLogs(ctx context.Context, limit int) ([]AuditLog, error)
}

type service struct {
	repo Repository
}

func NewService(repo Repository) Service {
	return &service{repo: repo}
}

func (s *service) RecordMessageEvent(ctx context.Context, messageID uuid.UUID, queueID string, eventType EventType, status string, detail string) error {
	event := &MessageEvent{
		ID:        uuid.New(),
		MessageID: messageID,
		QueueID:   queueID,
		EventType: eventType,
		Status:    status,
		Detail:    detail,
	}
	return s.repo.CreateMessageEvent(ctx, event)
}

func (s *service) ListMessageEvents(ctx context.Context, messageID uuid.UUID) ([]MessageEvent, error) {
	return s.repo.ListMessageEventsByMessageID(ctx, messageID)
}

func (s *service) TraceMessage(ctx context.Context, messageID uuid.UUID) (*MessageTrace, error) {
	events, err := s.repo.ListMessageEventsByMessageID(ctx, messageID)
	if err != nil {
		return nil, err
	}

	trace := &MessageTrace{
		MessageID: messageID,
		Events:    events,
	}
	if len(events) > 0 {
		for _, e := range events {
			if e.QueueID != "" && trace.QueueID == "" {
				trace.QueueID = e.QueueID
			}
		}
	}

	return trace, nil
}

func (s *service) RecordAudit(ctx context.Context, actorType string, actorID *uuid.UUID, action string, resourceType string, resourceID *uuid.UUID, metadata any) error {
	var metaBytes json.RawMessage
	if metadata != nil {
		b, err := json.Marshal(metadata)
		if err == nil {
			metaBytes = b
		}
	}

	log := &AuditLog{
		ID:           uuid.New(),
		ActorType:    actorType,
		ActorID:      actorID,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Metadata:     metaBytes,
	}
	return s.repo.CreateAuditLog(ctx, log)
}

func (s *service) ListAuditLogs(ctx context.Context, limit int) ([]AuditLog, error) {
	return s.repo.ListAuditLogs(ctx, limit)
}
