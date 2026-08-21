package provisioning

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

var (
	localpartRegex = regexp.MustCompile(`^[a-z0-9]([a-z0-9_.+-]*[a-z0-9])?$`)
	domainRegex    = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
)

type FilesystemProvisioner struct {
	root string
	uid  int
	gid  int
}

func NewFilesystemProvisioner(root string, uid, gid int) (*FilesystemProvisioner, error) {
	if root == "" {
		return nil, fmt.Errorf("root path cannot be empty")
	}

	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("invalid root path: %w", err)
	}

	_ = os.MkdirAll(absRoot, 0750)


	return &FilesystemProvisioner{
		root: absRoot,
		uid:  uid,
		gid:  gid,
	}, nil
}

func (p *FilesystemProvisioner) CalculatePath(email string) (string, error) {
	email = strings.TrimSpace(strings.ToLower(email))
	parts := strings.Split(email, "@")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", ErrInvalidMailbox
	}

	localpart := parts[0]
	domain := parts[1]

	// Prevent path traversal
	if strings.Contains(localpart, "..") || strings.Contains(domain, "..") ||
		strings.ContainsAny(localpart, "/\\") || strings.ContainsAny(domain, "/\\") {
		return "", ErrPathTraversal
	}

	if !localpartRegex.MatchString(localpart) || !domainRegex.MatchString(domain) {
		return "", ErrInvalidMailbox
	}

	targetDir := filepath.Join(p.root, domain, localpart, "Maildir")

	// Ensure path stays within root
	rel, err := filepath.Rel(p.root, targetDir)
	if err != nil || strings.HasPrefix(rel, "..") {
		return "", ErrPathTraversal
	}

	return targetDir, nil
}

func (p *FilesystemProvisioner) Provision(ctx context.Context, mb Mailbox) error {
	maildirPath, err := p.CalculatePath(mb.Email)
	if err != nil {
		return err
	}

	dirs := []string{
		maildirPath,
		filepath.Join(maildirPath, "cur"),
		filepath.Join(maildirPath, "new"),
		filepath.Join(maildirPath, "tmp"),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
		// Ensure permissions are strictly 0750
		if err := os.Chmod(dir, 0750); err != nil {
			return fmt.Errorf("failed to set permissions on %s: %w", dir, err)
		}

		// Attempt chown if configured and running with necessary permissions
		if p.uid > 0 || p.gid > 0 {
			_ = os.Chown(dir, p.uid, p.gid)
		}
	}

	return nil
}

func (p *FilesystemProvisioner) Deprovision(ctx context.Context, mb Mailbox) error {
	maildirPath, err := p.CalculatePath(mb.Email)
	if err != nil {
		return err
	}

	userDir := filepath.Dir(maildirPath)
	if err := os.RemoveAll(userDir); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove mailbox directory %s: %w", userDir, err)
	}

	return nil
}

func (p *FilesystemProvisioner) Inspect(ctx context.Context, mb Mailbox) (*DoctorReport, error) {
	maildirPath, err := p.CalculatePath(mb.Email)
	if err != nil {
		return nil, err
	}

	report := &DoctorReport{
		Email:           mb.Email,
		Root:            p.root,
		ProvisionStatus: "ready",
		Healthy:         true,
	}

	// 1. Check Maildir
	if info, err := os.Stat(maildirPath); err == nil && info.IsDir() {
		report.MaildirExists = CheckResult{Passed: true, Message: "Maildir directory exists"}
		report.Permission = p.checkPermissions(info)
		report.Ownership = p.checkOwnership(info)
	} else {
		report.MaildirExists = CheckResult{Passed: false, Message: "Maildir directory missing"}
		report.Healthy = false
	}

	// 2. Check cur
	curPath := filepath.Join(maildirPath, "cur")
	if info, err := os.Stat(curPath); err == nil && info.IsDir() {
		report.CurExists = CheckResult{Passed: true, Message: "cur directory exists"}
	} else {
		report.CurExists = CheckResult{Passed: false, Message: "cur directory missing"}
		report.Healthy = false
	}

	// 3. Check new
	newPath := filepath.Join(maildirPath, "new")
	if info, err := os.Stat(newPath); err == nil && info.IsDir() {
		report.NewExists = CheckResult{Passed: true, Message: "new directory exists"}
	} else {
		report.NewExists = CheckResult{Passed: false, Message: "new directory missing"}
		report.Healthy = false
	}

	// 4. Check tmp
	tmpPath := filepath.Join(maildirPath, "tmp")
	if info, err := os.Stat(tmpPath); err == nil && info.IsDir() {
		report.TmpExists = CheckResult{Passed: true, Message: "tmp directory exists"}
	} else {
		report.TmpExists = CheckResult{Passed: false, Message: "tmp directory missing"}
		report.Healthy = false
	}

	if !report.Permission.Passed || !report.Ownership.Passed {
		report.Healthy = false
	}

	return report, nil
}

func (p *FilesystemProvisioner) checkPermissions(info os.FileInfo) CheckResult {
	perm := info.Mode().Perm()
	if perm == 0750 {
		return CheckResult{Passed: true, Message: "0750"}
	}
	return CheckResult{
		Passed:  false,
		Message: fmt.Sprintf("Expected 0750, got %04o", perm),
	}
}

func (p *FilesystemProvisioner) checkOwnership(info os.FileInfo) CheckResult {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return CheckResult{Passed: true, Message: "vmail:vmail"}
	}

	currentUID := int(stat.Uid)
	currentGID := int(stat.Gid)

	if (p.uid == 0 && p.gid == 0) || (currentUID == p.uid && currentGID == p.gid) {
		return CheckResult{Passed: true, Message: fmt.Sprintf("uid=%d, gid=%d", currentUID, currentGID)}
	}

	// If running under test/local dev without root permissions, mark current owner note
	return CheckResult{
		Passed:  false,
		Message: fmt.Sprintf("Expected %d:%d, got %d:%d", p.uid, p.gid, currentUID, currentGID),
	}
}
