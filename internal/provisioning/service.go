package provisioning

import (
	"context"
)

type Service interface {
	Provision(ctx context.Context, mb Mailbox) error
	Deprovision(ctx context.Context, mb Mailbox) error
	Inspect(ctx context.Context, mb Mailbox) (*DoctorReport, error)
}

type service struct {
	provisioner Provisioner
}

func NewService(provisioner Provisioner) Service {
	return &service{
		provisioner: provisioner,
	}
}

func (s *service) Provision(ctx context.Context, mb Mailbox) error {
	return s.provisioner.Provision(ctx, mb)
}

func (s *service) Deprovision(ctx context.Context, mb Mailbox) error {
	return s.provisioner.Deprovision(ctx, mb)
}

func (s *service) Inspect(ctx context.Context, mb Mailbox) (*DoctorReport, error) {
	return s.provisioner.Inspect(ctx, mb)
}
