package postfix

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
)

type CheckItem struct {
	Name    string `json:"name"`
	Passed  bool   `json:"passed"`
	Message string `json:"message"`
}

type DoctorReport struct {
	BinaryInstalled CheckItem   `json:"binary_installed"`
	ServiceStatus   CheckItem   `json:"service_status"`
	MainCF          CheckItem   `json:"main_cf"`
	DomainsCF       CheckItem   `json:"domains_cf"`
	MailboxesCF     CheckItem   `json:"mailboxes_cf"`
	AliasesCF       CheckItem   `json:"aliases_cf"`
	VmailRoot       CheckItem   `json:"vmail_root"`
	DBLookupDomains CheckItem   `json:"db_lookup_domains"`
	DBLookupMailbox CheckItem   `json:"db_lookup_mailbox"`
	DBLookupAlias   CheckItem   `json:"db_lookup_alias"`
	PostfixCheck    CheckItem   `json:"postfix_check"`
	Checks          []CheckItem `json:"checks"`
	Healthy         bool        `json:"healthy"`
}

func RunDoctor(ctx context.Context, repo Repository, configDir, vmailRoot string, vmailUID, vmailGID int) *DoctorReport {
	report := &DoctorReport{
		Healthy: true,
	}

	// 1. Postfix binary
	if path, err := exec.LookPath("postfix"); err == nil {
		report.BinaryInstalled = CheckItem{Name: "Postfix Binary", Passed: true, Message: path}
	} else {
		report.BinaryInstalled = CheckItem{Name: "Postfix Binary", Passed: false, Message: "not found in PATH"}
		// On non-Linux/dev systems without postfix, note this gracefully
	}
	report.Checks = append(report.Checks, report.BinaryInstalled)

	// 2. Postfix service status
	prov := NewSystemProvisioner(configDir)
	status, _ := prov.Status(ctx)
	report.ServiceStatus = CheckItem{Name: "Postfix Service", Passed: status == "running" || status == "stopped", Message: status}
	report.Checks = append(report.Checks, report.ServiceStatus)

	// 3. Check configuration files
	cfFiles := []struct {
		target *CheckItem
		name   string
		file   string
	}{
		{&report.MainCF, "main.cf", "main.cf"},
		{&report.DomainsCF, "virtual_mailbox_domains", "pgsql-virtual-mailbox-domains.cf"},
		{&report.MailboxesCF, "virtual_mailbox_maps", "pgsql-virtual-mailbox-maps.cf"},
		{&report.AliasesCF, "virtual_alias_maps", "pgsql-virtual-alias-maps.cf"},
	}

	for _, cf := range cfFiles {
		fullPath := filepath.Join(configDir, cf.file)
		info, err := os.Stat(fullPath)
		if err == nil {
			perm := info.Mode().Perm()
			*cf.target = CheckItem{Name: cf.name, Passed: true, Message: filepath.Base(fullPath)}
			if perm > 0640 {
				cf.target.Message += " (warning: permissions > 0640)"
			}
		} else {
			*cf.target = CheckItem{Name: cf.name, Passed: false, Message: "missing file"}
			report.Healthy = false
		}
		report.Checks = append(report.Checks, *cf.target)
	}

	// 4. Check Vmail Root
	if info, err := os.Stat(vmailRoot); err == nil && info.IsDir() {
		report.VmailRoot = CheckItem{Name: "Mail Root (/var/vmail)", Passed: true, Message: vmailRoot}
	} else {
		report.VmailRoot = CheckItem{Name: "Mail Root (/var/vmail)", Passed: false, Message: "missing root directory"}
		report.Healthy = false
	}
	report.Checks = append(report.Checks, report.VmailRoot)

	// 5. Check Live PostgreSQL Lookups
	// 5.1 Domain lookup
	_, err := repo.LookupVirtualDomain(ctx, "example.com")
	if err == nil {
		report.DBLookupDomains = CheckItem{Name: "PostgreSQL Domain Lookup", Passed: true, Message: "query active"}
	} else {
		report.DBLookupDomains = CheckItem{Name: "PostgreSQL Domain Lookup", Passed: false, Message: err.Error()}
		report.Healthy = false
	}
	report.Checks = append(report.Checks, report.DBLookupDomains)

	// 5.2 Mailbox lookup
	_, err = repo.LookupVirtualMailbox(ctx, "ajar@example.com")
	if err == nil {
		report.DBLookupMailbox = CheckItem{Name: "PostgreSQL Mailbox Lookup", Passed: true, Message: "query active (filtered by ready status)"}
	} else {
		report.DBLookupMailbox = CheckItem{Name: "PostgreSQL Mailbox Lookup", Passed: false, Message: err.Error()}
		report.Healthy = false
	}
	report.Checks = append(report.Checks, report.DBLookupMailbox)

	// 5.3 Alias lookup
	_, err = repo.LookupVirtualAlias(ctx, "support@example.com")
	if err == nil {
		report.DBLookupAlias = CheckItem{Name: "PostgreSQL Alias Lookup", Passed: true, Message: "query active"}
	} else {
		report.DBLookupAlias = CheckItem{Name: "PostgreSQL Alias Lookup", Passed: false, Message: err.Error()}
		report.Healthy = false
	}
	report.Checks = append(report.Checks, report.DBLookupAlias)

	// 6. Postfix Syntax Check
	if err := prov.Validate(ctx); err == nil {
		report.PostfixCheck = CheckItem{Name: "Postfix Check (syntax)", Passed: true, Message: "OK"}
	} else {
		report.PostfixCheck = CheckItem{Name: "Postfix Check (syntax)", Passed: false, Message: err.Error()}
		if report.BinaryInstalled.Passed {
			report.Healthy = false
		}
	}
	report.Checks = append(report.Checks, report.PostfixCheck)

	return report
}
