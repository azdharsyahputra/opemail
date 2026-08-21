package queue

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

var validQueueIDRegex = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

func validateQueueID(queueID string) error {
	queueID = strings.TrimSpace(queueID)
	if queueID == "" || !validQueueIDRegex.MatchString(queueID) {
		return fmt.Errorf("invalid queue ID format %q: must be alphanumeric, hyphen or underscore", queueID)
	}
	return nil
}


type Service interface {
	GetStatus(ctx context.Context) (*QueueSummary, error)
	List(ctx context.Context, filterStatus string) ([]QueueMessage, error)
	Inspect(ctx context.Context, queueID string) (string, error)
	Retry(ctx context.Context, queueID string) error
	Delete(ctx context.Context, queueID string) error
	Hold(ctx context.Context, queueID string) error
	Release(ctx context.Context, queueID string) error
	Flush(ctx context.Context) error
}

type service struct {
	driver Driver
}

func NewService(driver Driver) Service {
	return &service{driver: driver}
}

func (s *service) GetStatus(ctx context.Context) (*QueueSummary, error) {
	out, err := s.driver.ListQueueRaw(ctx)
	if err != nil && !strings.Contains(out, "Mail queue is empty") {
		return nil, err
	}
	_, summary, err := ParseQueueOutput(out)
	if err != nil {
		return nil, err
	}
	return summary, nil
}

func (s *service) List(ctx context.Context, filterStatus string) ([]QueueMessage, error) {
	out, err := s.driver.ListQueueRaw(ctx)
	if err != nil && !strings.Contains(out, "Mail queue is empty") {
		return nil, err
	}
	messages, _, err := ParseQueueOutput(out)
	if err != nil {
		return nil, err
	}

	if filterStatus == "" {
		return messages, nil
	}

	filterLower := strings.ToLower(strings.TrimSpace(filterStatus))
	var filtered []QueueMessage
	for _, m := range messages {
		if strings.ToLower(string(m.Status)) == filterLower {
			filtered = append(filtered, m)
		}
	}
	return filtered, nil
}

func (s *service) Inspect(ctx context.Context, queueID string) (string, error) {
	if err := validateQueueID(queueID); err != nil {
		return "", err
	}
	return s.driver.InspectMessage(ctx, queueID)
}

func (s *service) Retry(ctx context.Context, queueID string) error {
	if err := validateQueueID(queueID); err != nil {
		return err
	}
	return s.driver.RequeueMessage(ctx, queueID)
}

func (s *service) Delete(ctx context.Context, queueID string) error {
	if err := validateQueueID(queueID); err != nil {
		return err
	}
	return s.driver.DeleteMessage(ctx, queueID)
}

func (s *service) Hold(ctx context.Context, queueID string) error {
	if err := validateQueueID(queueID); err != nil {
		return err
	}
	return s.driver.HoldMessage(ctx, queueID)
}

func (s *service) Release(ctx context.Context, queueID string) error {
	if err := validateQueueID(queueID); err != nil {
		return err
	}
	return s.driver.ReleaseMessage(ctx, queueID)
}

func (s *service) Flush(ctx context.Context) error {
	return s.driver.FlushQueue(ctx)
}
