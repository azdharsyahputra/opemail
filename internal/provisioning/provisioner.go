package provisioning

import (
	"context"
	"errors"
)

var (
	ErrInvalidMailbox  = errors.New("invalid mailbox identity")
	ErrPathTraversal   = errors.New("path traversal detected in mailbox identity")
	ErrPermissionDenied = errors.New("permission denied during mailbox provisioning")
)

type Mailbox struct {
	ID         string
	Email      string
	Domain     string
	QuotaBytes int64
}

type CheckResult struct {
	Passed  bool   `json:"passed"`
	Message string `json:"message"`
}

type DoctorReport struct {
	Email           string      `json:"email"`
	Status          string      `json:"status"`
	ProvisionStatus string      `json:"provision_status"`
	Root            string      `json:"root"`
	MaildirExists   CheckResult `json:"maildir_exists"`
	CurExists       CheckResult `json:"cur_exists"`
	NewExists       CheckResult `json:"new_exists"`
	TmpExists       CheckResult `json:"tmp_exists"`
	Ownership       CheckResult `json:"ownership"`
	Permission      CheckResult `json:"permission"`
	Healthy         bool        `json:"healthy"`
}

type Provisioner interface {
	Provision(ctx context.Context, mailbox Mailbox) error
	Deprovision(ctx context.Context, mailbox Mailbox) error
	Inspect(ctx context.Context, mailbox Mailbox) (*DoctorReport, error)
}
