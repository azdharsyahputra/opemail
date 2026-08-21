package queue_test

import (
	"context"
	"testing"

	"github.com/azdharsyahputra/openmail/internal/queue"
)

type mockQueueDriver struct {
	rawOutput string
}

func (m *mockQueueDriver) ListQueueRaw(ctx context.Context) (string, error) {
	return m.rawOutput, nil
}
func (m *mockQueueDriver) InspectMessage(ctx context.Context, queueID string) (string, error) {
	return "Mock Message Content for " + queueID, nil
}
func (m *mockQueueDriver) DeleteMessage(ctx context.Context, queueID string) error  { return nil }
func (m *mockQueueDriver) HoldMessage(ctx context.Context, queueID string) error    { return nil }
func (m *mockQueueDriver) ReleaseMessage(ctx context.Context, queueID string) error { return nil }
func (m *mockQueueDriver) RequeueMessage(ctx context.Context, queueID string) error { return nil }
func (m *mockQueueDriver) FlushQueue(ctx context.Context) error                     { return nil }

func TestQueueParser(t *testing.T) {
	t.Run("Parse Empty Queue", func(t *testing.T) {
		msgs, summary, err := queue.ParseQueueOutput("Mail queue is empty")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(msgs) != 0 || summary.Total != 0 {
			t.Errorf("expected empty summary, got %d messages", summary.Total)
		}
	})

	t.Run("Parse Postfix Text Output", func(t *testing.T) {
		sample := `-Queue ID- --Size-- ----Arrival Time---- -Sender/Recipient-------
A82F91       1024 Fri Aug 21 22:01:12  sender@example.com
(host mail.receiver.com[198.51.100.1] said: 451 4.7.1 Try again later)
                                         user@gmail.com

B19AC2*      2048 Fri Aug 21 22:05:00  admin@example.net
                                         test@yahoo.com

C33D44!       512 Fri Aug 21 22:06:30  internal@local.com
                                         quarantined@external.com

-- 3 Kbytes in 3 Requests.
`
		msgs, summary, err := queue.ParseQueueOutput(sample)
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}

		if len(msgs) != 3 || summary.Total != 3 {
			t.Fatalf("expected 3 messages, got %d", len(msgs))
		}

		// Message 1: Deferred
		if msgs[0].QueueID != "A82F91" || msgs[0].Status != queue.StatusDeferred {
			t.Errorf("msg[0] expected A82F91 deferred, got %s / %s", msgs[0].QueueID, msgs[0].Status)
		}
		if msgs[0].Recipient != "user@gmail.com" {
			t.Errorf("msg[0] expected user@gmail.com, got %s", msgs[0].Recipient)
		}
		if msgs[0].Reason != "host mail.receiver.com[198.51.100.1] said: 451 4.7.1 Try again later" {
			t.Errorf("msg[0] reason mismatch: %s", msgs[0].Reason)
		}

		// Message 2: Active
		if msgs[1].QueueID != "B19AC2" || msgs[1].Status != queue.StatusActive {
			t.Errorf("msg[1] expected B19AC2 active, got %s / %s", msgs[1].QueueID, msgs[1].Status)
		}

		// Message 3: Hold
		if msgs[2].QueueID != "C33D44" || msgs[2].Status != queue.StatusHold {
			t.Errorf("msg[2] expected C33D44 hold, got %s / %s", msgs[2].QueueID, msgs[2].Status)
		}

		if summary.Active != 1 || summary.Deferred != 1 || summary.Hold != 1 {
			t.Errorf("summary counts mismatch: %+v", summary)
		}
	})

	t.Run("Queue Service Filter by Status", func(t *testing.T) {
		sample := `-Queue ID- --Size-- ----Arrival Time---- -Sender/Recipient-------
A82F91       1024 Fri Aug 21 22:01:12  sender@example.com
(host mail.receiver.com[198.51.100.1] said: 451 4.7.1 Try again later)
                                         user@gmail.com
B19AC2*      2048 Fri Aug 21 22:05:00  admin@example.net
                                         test@yahoo.com
`
		svc := queue.NewService(&mockQueueDriver{rawOutput: sample})
		ctx := context.Background()

		deferred, err := svc.List(ctx, "deferred")
		if err != nil {
			t.Fatalf("list error: %v", err)
		}
		if len(deferred) != 1 || deferred[0].QueueID != "A82F91" {
			t.Errorf("expected 1 deferred message, got %d", len(deferred))
		}

		active, err := svc.List(ctx, "active")
		if err != nil {
			t.Fatalf("list active error: %v", err)
		}
		if len(active) != 1 || active[0].QueueID != "B19AC2" {
			t.Errorf("expected 1 active message, got %d", len(active))
		}
	})
}
