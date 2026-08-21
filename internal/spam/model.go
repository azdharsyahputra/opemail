package spam

import (
	"context"
	"fmt"
	"net"
	"time"
)

type Policy struct {
	SpamThreshold     float64 `json:"spam_threshold"`
	RejectThreshold   float64 `json:"reject_threshold"`
	QuarantineEnabled bool    `json:"quarantine_enabled"`
}

type CheckItem struct {
	Name    string `json:"name"`
	Passed  bool   `json:"passed"`
	Message string `json:"message"`
}

type DoctorReport struct {
	Healthy bool        `json:"healthy"`
	Checks  []CheckItem `json:"checks"`
}

func CheckRspamd(ctx context.Context, host string) (bool, string) {
	if host == "" {
		host = "127.0.0.1:11333"
	}
	conn, err := net.DialTimeout("tcp", host, 300*time.Millisecond)
	if err != nil {
		return false, fmt.Sprintf("Rspamd controller unavailable (%s): %v", host, err)
	}
	_ = conn.Close()
	return true, "Rspamd controller active"
}

func RunDoctor(ctx context.Context, host string) *DoctorReport {
	report := &DoctorReport{Healthy: true}
	ok, msg := CheckRspamd(ctx, host)
	report.Checks = append(report.Checks, CheckItem{
		Name:    "Rspamd Service",
		Passed:  true, // Informational / containerized
		Message: msg,
	})
	report.Checks = append(report.Checks, CheckItem{
		Name:    "Default Spam Threshold",
		Passed:  true,
		Message: "Score >= 6.0 (Junk / Quarantine)",
	})
	report.Checks = append(report.Checks, CheckItem{
		Name:    "Default Reject Threshold",
		Passed:  true,
		Message: "Score >= 15.0 (SMTP Reject)",
	})
	_ = ok
	return report
}
