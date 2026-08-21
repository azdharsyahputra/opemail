package quota

import (
	"context"
	"strings"

	"github.com/azdharsyahputra/openmail/internal/mailbox"
	"github.com/azdharsyahputra/openmail/internal/provisioning"
)

type Service interface {
	GetQuota(ctx context.Context, email string) (*MailboxQuota, error)
	CheckCanAccept(ctx context.Context, email string, incomingBytes int64) (bool, error)
	Reconcile(ctx context.Context, email string) (*MailboxQuota, error)
}

type service struct {
	mailboxRepo mailbox.Repository
	provisioner provisioning.Provisioner
}

func NewService(mailboxRepo mailbox.Repository, provisioner provisioning.Provisioner) Service {
	return &service{
		mailboxRepo: mailboxRepo,
		provisioner: provisioner,
	}
}

func (s *service) GetQuota(ctx context.Context, email string) (*MailboxQuota, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	mb, err := s.mailboxRepo.GetByEmail(ctx, email)
	if err != nil {
		return nil, err
	}

	status, pct, isExceeded := ComputeStatus(mb.UsedBytes, mb.QuotaBytes)
	return &MailboxQuota{
		MailboxID:    mb.ID,
		Email:        mb.Email,
		UsedBytes:    mb.UsedBytes,
		QuotaBytes:   mb.QuotaBytes,
		UsagePercent: pct,
		Status:       status,
		IsExceeded:   isExceeded,
	}, nil
}

func (s *service) CheckCanAccept(ctx context.Context, email string, incomingBytes int64) (bool, error) {
	q, err := s.GetQuota(ctx, email)
	if err != nil {
		return false, err
	}

	if q.QuotaBytes > 0 && (q.UsedBytes+incomingBytes) > q.QuotaBytes {
		return false, ErrQuotaExceeded
	}
	return true, nil
}

func (s *service) Reconcile(ctx context.Context, email string) (*MailboxQuota, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	mb, err := s.mailboxRepo.GetByEmail(ctx, email)
	if err != nil {
		return nil, err
	}

	var scan StorageScanResult
	if s.provisioner != nil {
		if fsProv, ok := s.provisioner.(*provisioning.FilesystemProvisioner); ok {
			maildirPath, err := fsProv.CalculatePath(email)
			if err == nil {
				scan, _ = CalculateMaildirUsage(maildirPath)
			}
		}
	}

	// Update DB record
	_ = s.mailboxRepo.UpdateUsedBytes(ctx, mb.ID, scan.TotalBytes)


	status, pct, isExceeded := ComputeStatus(scan.TotalBytes, mb.QuotaBytes)
	return &MailboxQuota{
		MailboxID:    mb.ID,
		Email:        mb.Email,
		UsedBytes:    scan.TotalBytes,
		QuotaBytes:   mb.QuotaBytes,
		UsagePercent: pct,
		Status:       status,
		IsExceeded:   isExceeded,
		MessageCount: scan.MessageCount,
	}, nil
}
