package tls

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type CheckItem struct {
	Category string `json:"category"`
	Name     string `json:"name"`
	Passed   bool   `json:"passed"`
	Message  string `json:"message"`
}

type DoctorReport struct {
	Hostname string      `json:"hostname"`
	Checks   []CheckItem `json:"checks"`
	Healthy  bool        `json:"healthy"`
}

func RunDoctor(ctx context.Context, provider CertificateProvider, hostname string, postfixConfigDir, dovecotConfigDir string) *DoctorReport {
	report := &DoctorReport{
		Hostname: hostname,
		Healthy:  true,
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

	certPath, keyPath := provider.GetPaths(hostname)

	// 1. Certificate Checks
	certBytes, err := os.ReadFile(certPath)
	certExists := err == nil
	addCheck("Certificate", "File exists", certExists, certPath)

	keyBytes, err := os.ReadFile(keyPath)
	keyExists := err == nil
	addCheck("Certificate", "Key exists", keyExists, keyPath)

	if certExists && keyExists {
		valRep, certModel, valErr := ValidateBytes(certBytes, keyBytes, hostname)
		addCheck("Certificate", "PEM valid", valRep.CertificateOK, "x509 parse")
		addCheck("Certificate", "Private key valid", valRep.PrivateKeyOK, "key parse")
		addCheck("Certificate", "Key Match", valRep.KeyMatches, "public/private match")
		addCheck("Certificate", "Hostname Match", valRep.HostnameMatches, hostname)

		expiredMsg := fmt.Sprintf("%d days remaining (expires %s)", valRep.DaysRemaining, valRep.NotAfter.Format("2006-01-02"))
		addCheck("Validity", "Not expired", !valRep.Expired, expiredMsg)
		report.Checks = append(report.Checks, CheckItem{
			Category: "Validity",
			Name:     "Remaining > 30 days",
			Passed:   valRep.DaysRemaining > 30,
			Message:  fmt.Sprintf("%d days (%s)", valRep.DaysRemaining, valRep.Status),
		})


		if certModel != nil && len(certModel.DNSNames) > 0 {
			addCheck("Certificate", "SANs", true, strings.Join(certModel.DNSNames, ", "))
		}
		if valErr != nil && valRep.Expired {
			report.Healthy = false
		}
	} else {
		addCheck("Certificate", "Validation", false, "cannot validate missing files")
	}

	// 2. Permissions Checks
	if info, err := os.Stat(certPath); err == nil {
		perm := info.Mode().Perm()
		addCheck("Permissions", "Certificate 0644", perm <= 0644, fmt.Sprintf("%04o", perm))
	}
	if info, err := os.Stat(keyPath); err == nil {
		perm := info.Mode().Perm()
		addCheck("Permissions", "Private Key 0600", perm == 0600, fmt.Sprintf("%04o", perm))
	}

	// 3. Postfix Config Checks
	mainCFPath := filepath.Join(postfixConfigDir, "main.cf")
	if data, err := os.ReadFile(mainCFPath); err == nil {
		content := string(data)
		hasMay := strings.Contains(content, "smtpd_tls_security_level = may")
		addCheck("Postfix :25", "STARTTLS", hasMay, "may")
		noAuth25 := !strings.Contains(content, "smtpd_sasl_auth_enable = yes")
		addCheck("Postfix :25", "SMTP AUTH", noAuth25, "DISABLED")
	}

	masterCFPath := filepath.Join(postfixConfigDir, "master.cf")
	if data, err := os.ReadFile(masterCFPath); err == nil {
		content := string(data)
		hasEncrypt := strings.Contains(content, "smtpd_tls_security_level=encrypt")
		addCheck("Postfix :587", "STARTTLS", hasEncrypt, "REQUIRED")
		hasSASL := strings.Contains(content, "smtpd_sasl_auth_enable=yes")
		addCheck("Postfix :587", "SMTP AUTH", hasSASL, "REQUIRED")
		hasPlainBlocked := strings.Contains(content, "smtpd_tls_auth_only=yes") || hasEncrypt
		addCheck("Postfix :587", "Plain AUTH", hasPlainBlocked, "BLOCKED before TLS")
	}

	// 4. Dovecot Config Checks
	dovecotMailConf := filepath.Join(dovecotConfigDir, "conf.d/10-ssl.conf")
	if data, err := os.ReadFile(dovecotMailConf); err == nil {
		content := string(data)
		hasSSLReq := strings.Contains(content, "ssl = required") || strings.Contains(content, "ssl = yes")
		addCheck("Dovecot :993", "TLS", hasSSLReq, "REQUIRED")
		addCheck("Dovecot :143", "STARTTLS", hasSSLReq, "available")
		hasMinTLS := strings.Contains(content, "ssl_min_protocol = TLSv1.2")
		addCheck("Protocols", "Min Protocol TLS 1.2", hasMinTLS, "TLSv1.2")
	}

	// 5. Live Socket / TLS Handshake Checks (if running)
	if conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 500 * time.Millisecond}, "tcp", "127.0.0.1:993", &tls.Config{InsecureSkipVerify: true}); err == nil {
		state := conn.ConnectionState()
		_ = conn.Close()
		verStr := tlsVersionToString(state.Version)
		addCheck("Protocols", "Live IMAPS :993 Handshake", true, verStr)
	}

	return report
}

func tlsVersionToString(ver uint16) string {
	switch ver {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", ver)
	}
}
