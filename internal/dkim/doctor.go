package dkim

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

type CheckItem struct {
	Category string `json:"category"`
	Name     string `json:"name"`
	Passed   bool   `json:"passed"`
	Message  string `json:"message"`
}

type DoctorReport struct {
	Domain   string      `json:"domain"`
	Healthy  bool        `json:"healthy"`
	Checks   []CheckItem `json:"checks"`
}

func RunDKIMDoctor(ctx context.Context, svc Service, domainName string, customLookup func(string) ([]string, error)) *DoctorReport {
	domainName = strings.ToLower(strings.TrimSpace(domainName))
	report := &DoctorReport{
		Domain:  domainName,
		Healthy: true,
	}

	addCheck := func(category, name string, passed bool, message string) {
		report.Checks = append(report.Checks, CheckItem{
			Category: category,
			Name:     name,
			Passed:   passed,
			Message:  message,
		})
		if !passed {
			report.Healthy = false
		}
	}

	keys, err := svc.ListKeys(ctx, domainName)
	if err != nil || len(keys) == 0 {
		addCheck("DKIM Key", "Key exists in database", false, "No DKIM keys found for domain")
		return report
	}

	for _, k := range keys {
		sel := k.Selector
		category := fmt.Sprintf("DKIM [%s]", sel)

		addCheck(category, "Database Status", true, fmt.Sprintf("Status: %s", k.Status))

		// Check private key in keystore
		keyPath := svc.Keystore().GetPrivateKeyPath(domainName, sel)
		info, err := os.Stat(keyPath)
		if err != nil {
			addCheck(category, "Private key file", false, fmt.Sprintf("Missing at %s", keyPath))
			continue
		}
		addCheck(category, "Private key file", true, keyPath)

		// Permissions
		perm := info.Mode().Perm()
		addCheck(category, "Private key 0600", perm <= 0600, fmt.Sprintf("%04o", perm))

		dirInfo, err := os.Stat(filepath.Dir(keyPath))
		if err == nil {
			dirPerm := dirInfo.Mode().Perm()
			addCheck(category, "Directory 0750", dirPerm <= 0750, fmt.Sprintf("%04o", dirPerm))
		}

		// Validate keypair match
		privBytes, err := svc.Keystore().GetPrivateKey(ctx, domainName, sel)
		if err != nil {
			addCheck(category, "Private key valid", false, err.Error())
			continue
		}

		if _, err := ValidatePrivateKey(privBytes); err != nil {
			addCheck(category, "Private key valid", false, err.Error())
			continue
		}
		addCheck(category, "Private key valid", true, "RSA-2048 valid")


		// DNS Verification
		verRes, _ := svc.VerifyDNS(ctx, domainName, sel, customLookup)
		if verRes != nil && verRes.DNSRecordFound {
			addCheck(category, "DNS TXT Record", true, verRes.DNSValue)
			addCheck(category, "Public Key Valid", verRes.PublicKeyValid, "Valid RSA PKIX")
			addCheck(category, "Key Match", verRes.KeyMatches, "DNS public key matches local private key")
		} else {
			// If key is active, missing DNS is a failure; if pending, it's informational
			isFail := k.Status == StatusActive
			report.Checks = append(report.Checks, CheckItem{
				Category: category,
				Name:     "DNS TXT Record",
				Passed:   !isFail,
				Message:  fmt.Sprintf("TXT record %s not found", BuildDNSName(domainName, sel)),
			})
			if isFail {
				report.Healthy = false
			}
		}
	}

	return report
}

// CheckMilterSocket verifies if Postfix OpenDKIM milter socket is active and responsive.
func CheckMilterSocket(socketPath string) (bool, string) {
	if socketPath == "" {
		socketPath = "/var/spool/postfix/private/opendkim"
	}
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return false, fmt.Sprintf("milter socket unavailable: %v", err)
	}
	_ = conn.Close()
	return true, "unix socket reachable"
}
