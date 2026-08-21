package dovecot

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

type CheckItem struct {
	Category string `json:"category"`
	Name     string `json:"name"`
	Passed   bool   `json:"passed"`
	Message  string `json:"message"`
}

type DoctorReport struct {
	ServiceChecks    []CheckItem `json:"service_checks"`
	ConfigChecks     []CheckItem `json:"config_checks"`
	DatabaseChecks   []CheckItem `json:"database_checks"`
	FilesystemChecks []CheckItem `json:"filesystem_checks"`
	ProtocolChecks   []CheckItem `json:"protocol_checks"`
	Healthy          bool        `json:"healthy"`
}

func RunDoctor(ctx context.Context, repo Repository, configDir, vmailRoot string, vmailUID, vmailGID int) *DoctorReport {
	report := &DoctorReport{
		Healthy: true,
	}

	// 1. Service Check
	prov := NewSystemProvisioner(configDir)
	status, _ := prov.Status(ctx)
	serviceCheck := CheckItem{
		Category: "Service",
		Name:     "dovecot",
		Passed:   status == "running" || status == "stopped",
		Message:  status,
	}
	report.ServiceChecks = append(report.ServiceChecks, serviceCheck)

	// Binary check
	if path, err := exec.LookPath("dovecot"); err == nil {
		report.ServiceChecks = append(report.ServiceChecks, CheckItem{
			Category: "Service",
			Name:     "dovecot binary",
			Passed:   true,
			Message:  path,
		})
	} else {
		report.ServiceChecks = append(report.ServiceChecks, CheckItem{
			Category: "Service",
			Name:     "dovecot binary",
			Passed:   false,
			Message:  "not installed in PATH",
		})
	}

	// 2. Configuration Files Check
	cfFiles := []struct {
		name string
		rel  string
	}{
		{"dovecot.conf", "dovecot.conf"},
		{"mail_location (10-mail.conf)", filepath.Join("conf.d", "10-mail.conf")},
		{"auth (10-auth.conf)", filepath.Join("conf.d", "10-auth.conf")},
		{"PostgreSQL (dovecot-pgsql.conf.ext)", filepath.Join("sql", "dovecot-pgsql.conf.ext")},
	}

	for _, item := range cfFiles {
		fullPath := filepath.Join(configDir, item.rel)
		info, err := os.Stat(fullPath)
		if err == nil {
			msg := item.rel
			if item.rel == filepath.Join("sql", "dovecot-pgsql.conf.ext") {
				if info.Mode().Perm() > 0640 {
					msg += " (warning: permissions > 0640)"
				}
			}
			report.ConfigChecks = append(report.ConfigChecks, CheckItem{
				Category: "Configuration",
				Name:     item.name,
				Passed:   true,
				Message:  msg,
			})
		} else {
			report.ConfigChecks = append(report.ConfigChecks, CheckItem{
				Category: "Configuration",
				Name:     item.name,
				Passed:   false,
				Message:  "missing file",
			})
			report.Healthy = false
		}
	}

	// 3. Database Check
	// 3.1 Auth query check
	_, err := repo.GetPasswordHash(ctx, "ajar@example.com")
	if err == nil || err == ErrUserNotFound {
		report.DatabaseChecks = append(report.DatabaseChecks, CheckItem{
			Category: "Database",
			Name:     "auth query (passdb)",
			Passed:   true,
			Message:  "active (filtered by ready status)",
		})
	} else {
		report.DatabaseChecks = append(report.DatabaseChecks, CheckItem{
			Category: "Database",
			Name:     "auth query (passdb)",
			Passed:   false,
			Message:  err.Error(),
		})
		report.Healthy = false
	}

	// 3.2 Userdb query check
	_, err = repo.GetUserInfo(ctx, "ajar@example.com", vmailRoot, vmailUID, vmailGID)
	if err == nil || err == ErrUserNotFound {
		report.DatabaseChecks = append(report.DatabaseChecks, CheckItem{
			Category: "Database",
			Name:     "userdb query (mailbox location)",
			Passed:   true,
			Message:  "active",
		})
	} else {
		report.DatabaseChecks = append(report.DatabaseChecks, CheckItem{
			Category: "Database",
			Name:     "userdb query (mailbox location)",
			Passed:   false,
			Message:  err.Error(),
		})
		report.Healthy = false
	}

	// 4. Filesystem Check
	if info, err := os.Stat(vmailRoot); err == nil && info.IsDir() {
		report.FilesystemChecks = append(report.FilesystemChecks, CheckItem{
			Category: "Filesystem",
			Name:     vmailRoot,
			Passed:   true,
			Message:  "directory exists",
		})
	} else {
		report.FilesystemChecks = append(report.FilesystemChecks, CheckItem{
			Category: "Filesystem",
			Name:     vmailRoot,
			Passed:   false,
			Message:  "directory missing",
		})
		report.Healthy = false
	}

	report.FilesystemChecks = append(report.FilesystemChecks, CheckItem{
		Category: "Filesystem",
		Name:     "vmail UID / GID",
		Passed:   true,
		Message:  fmt.Sprintf("UID=%d, GID=%d", vmailUID, vmailGID),
	})

	// 5. Protocol Check (IMAP :143)
	conn, err := net.DialTimeout("tcp", "127.0.0.1:143", 500*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		report.ProtocolChecks = append(report.ProtocolChecks, CheckItem{
			Category: "Protocols",
			Name:     "IMAP :143",
			Passed:   true,
			Message:  "listening",
		})
	} else {
		report.ProtocolChecks = append(report.ProtocolChecks, CheckItem{
			Category: "Protocols",
			Name:     "IMAP :143",
			Passed:   false,
			Message:  "port closed / service down",
		})
	}

	return report
}
