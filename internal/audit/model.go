package audit

import (
	"encoding/json"
	"net"
	"time"

	"github.com/google/uuid"
)

type EventType string

const (
	EventReceived        EventType = "received"
	EventAuthenticated   EventType = "authenticated"
	EventQueued          EventType = "queued"
	EventDeliveryAttempt EventType = "delivery_attempt"
	EventDelivered       EventType = "delivered"
	EventDeferred        EventType = "deferred"
	EventBounced         EventType = "bounced"
	EventSpamDetected    EventType = "spam_detected"
	EventMalwareDetected EventType = "malware_detected"
	EventDeleted         EventType = "deleted"
)

type MessageEvent struct {
	ID        uuid.UUID `json:"id"`
	MessageID uuid.UUID `json:"message_id,omitempty"`
	QueueID   string    `json:"queue_id,omitempty"`
	EventType EventType `json:"event_type"`
	Status    string    `json:"status"` // pass, fail, ok, error, deferred, bounced
	Detail    string    `json:"detail,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type AuditLog struct {
	ID           uuid.UUID       `json:"id"`
	ActorType    string          `json:"actor_type"` // admin, system, user
	ActorID      *uuid.UUID      `json:"actor_id,omitempty"`
	Action       string          `json:"action"` // mailbox.create, mailbox.password.change, dkim.rotate, etc.
	ResourceType string          `json:"resource_type"` // domain, mailbox, dkim, policy
	ResourceID   *uuid.UUID      `json:"resource_id,omitempty"`
	Metadata     json.RawMessage `json:"metadata,omitempty"`
	IPAddress    net.IP          `json:"ip_address,omitempty"`
	CreatedAt    time.Time       `json:"created_at"`
}

type MessageTrace struct {
	MessageID uuid.UUID      `json:"message_id"`
	QueueID   string         `json:"queue_id,omitempty"`
	From      string         `json:"from,omitempty"`
	To        string         `json:"to,omitempty"`
	Subject   string         `json:"subject,omitempty"`
	Events    []MessageEvent `json:"events"`
}
