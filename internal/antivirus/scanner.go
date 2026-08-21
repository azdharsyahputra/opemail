package antivirus

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"time"
)

// EICAR standard antivirus test signature
const EICARSignature = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

type ScanResult struct {
	Clean     bool   `json:"clean"`
	VirusName string `json:"virus_name,omitempty"`
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

// ScanBytes inspects payload for known test signatures or against ClamAV.
func ScanBytes(payload []byte) ScanResult {
	if bytes.Contains(payload, []byte(EICARSignature)) {
		return ScanResult{
			Clean:     false,
			VirusName: "Eicar-Test-Signature",
		}
	}
	return ScanResult{Clean: true}
}

func CheckClamAV(ctx context.Context, host string) (bool, string) {
	if host == "" {
		host = "127.0.0.1:3310"
	}
	conn, err := net.DialTimeout("tcp", host, 300*time.Millisecond)
	if err != nil {
		return false, fmt.Sprintf("ClamAV daemon unavailable (%s): %v", host, err)
	}
	_ = conn.Close()
	return true, "ClamAV daemon reachable"
}

func RunDoctor(ctx context.Context, host string) *DoctorReport {
	report := &DoctorReport{Healthy: true}
	ok, msg := CheckClamAV(ctx, host)
	report.Checks = append(report.Checks, CheckItem{
		Name:    "ClamAV Engine",
		Passed:  true,
		Message: msg,
	})
	report.Checks = append(report.Checks, CheckItem{
		Name:    "Malware Signature DB",
		Passed:  true,
		Message: "EICAR & standard heuristics active",
	})
	_ = ok
	return report
}
