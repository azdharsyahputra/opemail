package bounce

import (
	"context"
)

type Service interface {
	ProcessBounceText(ctx context.Context, text string) *BounceReport
	ProcessDSN(ctx context.Context, rawDSN string) *BounceReport
}

type service struct{}

func NewService() Service {
	return &service{}
}

func (s *service) ProcessBounceText(ctx context.Context, text string) *BounceReport {
	return ClassifyBounce(text)
}

func (s *service) ProcessDSN(ctx context.Context, rawDSN string) *BounceReport {
	return ParseDSN(rawDSN)
}
