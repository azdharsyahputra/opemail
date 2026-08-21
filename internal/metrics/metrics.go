package metrics

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
)

type Registry struct {
	mu sync.RWMutex

	// Counters
	SMTPConnectionsTotal atomic.Int64
	SMTPAuthSuccessTotal atomic.Int64
	SMTPAuthFailureTotal atomic.Int64

	MessagesReceivedTotal  atomic.Int64
	MessagesSentTotal      atomic.Int64
	MessagesDeliveredTotal atomic.Int64
	MessagesDeferredTotal  atomic.Int64
	MessagesBouncedTotal   atomic.Int64

	SpamDetectedTotal    atomic.Int64
	MalwareDetectedTotal atomic.Int64

	IMAPLoginsTotal       atomic.Int64
	IMAPAuthFailuresTotal atomic.Int64

	// Gauges
	QueueActive   atomic.Int64
	QueueDeferred atomic.Int64
	QueueHold     atomic.Int64

	MailboxStorageBytes atomic.Int64
	MailboxMessageCount atomic.Int64
}

var DefaultRegistry = &Registry{}

func (r *Registry) RenderPrometheus() string {
	var sb strings.Builder

	writeCounter := func(name, help string, val int64) {
		sb.WriteString(fmt.Sprintf("# HELP %s %s\n", name, help))
		sb.WriteString(fmt.Sprintf("# TYPE %s counter\n", name))
		sb.WriteString(fmt.Sprintf("%s %d\n\n", name, val))
	}

	writeGauge := func(name, help string, val int64) {
		sb.WriteString(fmt.Sprintf("# HELP %s %s\n", name, help))
		sb.WriteString(fmt.Sprintf("# TYPE %s gauge\n", name))
		sb.WriteString(fmt.Sprintf("%s %d\n\n", name, val))
	}

	writeCounter("smtp_connections_total", "Total inbound and submission SMTP connections", r.SMTPConnectionsTotal.Load())
	writeCounter("smtp_auth_success_total", "Total successful SMTP authentications", r.SMTPAuthSuccessTotal.Load())
	writeCounter("smtp_auth_failure_total", "Total failed SMTP authentications", r.SMTPAuthFailureTotal.Load())

	writeCounter("messages_received_total", "Total incoming messages received", r.MessagesReceivedTotal.Load())
	writeCounter("messages_sent_total", "Total outbound messages submitted", r.MessagesSentTotal.Load())
	writeCounter("messages_delivered_total", "Total messages successfully delivered to Maildir", r.MessagesDeliveredTotal.Load())
	writeCounter("messages_deferred_total", "Total messages deferred in Postfix queue", r.MessagesDeferredTotal.Load())
	writeCounter("messages_bounced_total", "Total messages bounced", r.MessagesBouncedTotal.Load())

	writeCounter("spam_detected_total", "Total spam messages classified", r.SpamDetectedTotal.Load())
	writeCounter("malware_detected_total", "Total malware/virus infected messages blocked", r.MalwareDetectedTotal.Load())

	writeCounter("imap_logins_total", "Total IMAP session logins", r.IMAPLoginsTotal.Load())
	writeCounter("imap_auth_failures_total", "Total failed IMAP authentication attempts", r.IMAPAuthFailuresTotal.Load())

	writeGauge("queue_active", "Current number of messages in Postfix active queue", r.QueueActive.Load())
	writeGauge("queue_deferred", "Current number of messages in Postfix deferred queue", r.QueueDeferred.Load())
	writeGauge("queue_hold", "Current number of messages in Postfix hold queue", r.QueueHold.Load())

	writeGauge("mailbox_storage_bytes", "Total storage bytes across all mailboxes", r.MailboxStorageBytes.Load())
	writeGauge("mailbox_message_count", "Total message count across all mailboxes", r.MailboxMessageCount.Load())

	return sb.String()
}

func Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = w.Write([]byte(DefaultRegistry.RenderPrometheus()))
	}
}
