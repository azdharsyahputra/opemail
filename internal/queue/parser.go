package queue

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ParseQueueOutput parses postqueue -p (or mailq) output into QueueMessage structs.
func ParseQueueOutput(output string) ([]QueueMessage, *QueueSummary, error) {
	summary := &QueueSummary{}
	output = strings.TrimSpace(output)
	if output == "" || strings.Contains(output, "Mail queue is empty") {
		return nil, summary, nil
	}

	// Try JSON line parsing first (postqueue -j)
	if strings.HasPrefix(output, "{") {
		messages, err := parseJSONQueue(output)
		if err == nil && len(messages) > 0 {
			populateSummary(summary, messages)
			return messages, summary, nil
		}
	}

	lines := strings.Split(output, "\n")
	var messages []QueueMessage
	var current *QueueMessage

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)

		// Header or footer line
		if strings.HasPrefix(line, "-Queue ID-") || strings.HasPrefix(trimmed, "-- ") {
			continue
		}
		if trimmed == "" {
			continue
		}

		// Check if start of a new queue entry (Queue ID in column 0)
		fields := strings.Fields(line)
		if len(fields) >= 5 && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") && !strings.HasPrefix(line, "(") {
			if current != nil {
				messages = append(messages, *current)
			}

			rawID := fields[0]
			status := StatusDeferred
			if strings.HasSuffix(rawID, "*") {
				status = StatusActive
				rawID = strings.TrimSuffix(rawID, "*")
			} else if strings.HasSuffix(rawID, "!") {
				status = StatusHold
				rawID = strings.TrimSuffix(rawID, "!")
			}

			size, _ := strconv.ParseInt(fields[1], 10, 64)
			sender := fields[len(fields)-1]

			// Parse date if possible (e.g. Fri Aug 21 22:01:12)
			var arrival time.Time
			if len(fields) >= 6 {
				dateStr := strings.Join(fields[2:len(fields)-1], " ")
				parsed, err := time.Parse("Mon Jan 2 15:04:05", dateStr)
				if err == nil {
					arrival = parsed
				}
			}
			if arrival.IsZero() {
				arrival = time.Now()
			}

			current = &QueueMessage{
				QueueID:     rawID,
				Size:        size,
				ArrivalDate: arrival,
				Sender:      sender,
				Status:      status,
			}
			continue
		}

		if current != nil {
			if strings.HasPrefix(trimmed, "(") && strings.HasSuffix(trimmed, ")") {
				current.Reason = strings.TrimSuffix(strings.TrimPrefix(trimmed, "("), ")")
			} else if !strings.HasPrefix(trimmed, "(") {
				current.Recipient = trimmed
			}
		}
	}

	if current != nil {
		messages = append(messages, *current)
	}

	populateSummary(summary, messages)
	return messages, summary, nil
}

func parseJSONQueue(output string) ([]QueueMessage, error) {
	lines := strings.Split(output, "\n")
	var messages []QueueMessage

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || !strings.HasPrefix(trimmed, "{") {
			continue
		}

		var raw struct {
			QueueID     string `json:"queue_id"`
			QueueName   string `json:"queue_name"`
			Size        int64  `json:"message_size"`
			ArrivalTime int64  `json:"arrival_time"`
			Sender      string `json:"sender"`
			Recipients  []struct {
				Address string `json:"address"`
				Reason  string `json:"delay_reason"`
			} `json:"recipients"`
		}

		if err := json.Unmarshal([]byte(trimmed), &raw); err != nil {
			continue
		}

		status := StatusDeferred
		switch raw.QueueName {
		case "active":
			status = StatusActive
		case "hold":
			status = StatusHold
		case "incoming":
			status = StatusIncoming
		case "corrupt":
			status = StatusCorrupt
		}

		var rcpt string
		var reason string
		if len(raw.Recipients) > 0 {
			rcpt = raw.Recipients[0].Address
			reason = raw.Recipients[0].Reason
		}

		arrival := time.Unix(raw.ArrivalTime, 0)
		messages = append(messages, QueueMessage{
			QueueID:     raw.QueueID,
			Size:        raw.Size,
			ArrivalDate: arrival,
			Sender:      raw.Sender,
			Recipient:   rcpt,
			Status:      status,
			Reason:      reason,
		})
	}

	return messages, nil
}

func populateSummary(summary *QueueSummary, messages []QueueMessage) {
	summary.Total = len(messages)
	var oldest *QueueMessage

	for i := range messages {
		m := &messages[i]
		m.Age = formatAge(m.ArrivalDate)

		switch m.Status {
		case StatusActive:
			summary.Active++
		case StatusDeferred:
			summary.Deferred++
		case StatusHold:
			summary.Hold++
		case StatusBounce:
			summary.Bounce++
		case StatusCorrupt:
			summary.Corrupt++
		case StatusIncoming:
			summary.Incoming++
		}

		if oldest == nil || m.ArrivalDate.Before(oldest.ArrivalDate) {
			oldest = m
		}
	}

	summary.OldestMessage = oldest
}

func formatAge(t time.Time) string {
	d := time.Since(t)
	if d < 0 {
		return "0s"
	}
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	hours := int(d.Hours())
	mins := int(d.Minutes()) % 60
	return fmt.Sprintf("%dh %dm", hours, mins)
}
