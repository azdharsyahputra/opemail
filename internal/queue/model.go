package queue

import "time"

type QueueStatus string

const (
	StatusActive   QueueStatus = "active"
	StatusDeferred QueueStatus = "deferred"
	StatusHold     QueueStatus = "hold"
	StatusBounce   QueueStatus = "bounce"
	StatusCorrupt  QueueStatus = "corrupt"
	StatusIncoming QueueStatus = "incoming"
	StatusUnknown  QueueStatus = "unknown"
)

type QueueMessage struct {
	QueueID     string      `json:"queue_id"`
	Size        int64       `json:"size"`
	ArrivalDate time.Time   `json:"arrival_date"`
	Sender      string      `json:"sender"`
	Recipient   string      `json:"recipient"`
	Status      QueueStatus `json:"status"`
	Reason      string      `json:"reason,omitempty"`
	Age         string      `json:"age"`
}

type QueueSummary struct {
	Active        int           `json:"active"`
	Deferred      int           `json:"deferred"`
	Hold          int           `json:"hold"`
	Bounce        int           `json:"bounce"`
	Corrupt       int           `json:"corrupt"`
	Incoming      int           `json:"incoming"`
	Total         int           `json:"total"`
	OldestMessage *QueueMessage `json:"oldest_message,omitempty"`
}
