package inbound

import (
	"fmt"
	"net"
	"strings"
)

// CheckPTR performs reverse DNS lookup for an IP address.
func CheckPTR(ip net.IP) ([]string, error) {
	names, err := net.LookupAddr(ip.String())
	if err != nil {
		return nil, err
	}
	return names, nil
}

// CheckFCrDNS performs Forward-Confirmed reverse DNS verification.
func CheckFCrDNS(ip net.IP) (bool, string, error) {
	ptrNames, err := CheckPTR(ip)
	if err != nil || len(ptrNames) == 0 {
		return false, "", err
	}

	for _, name := range ptrNames {
		cleanName := strings.TrimSuffix(name, ".")
		forwardIPs, err := net.LookupHost(cleanName)
		if err != nil {
			continue
		}
		for _, fIP := range forwardIPs {
			if fIP == ip.String() {
				return true, cleanName, nil
			}
		}
	}

	return false, ptrNames[0], nil
}

// CheckRBL queries a DNSBL zone for an IP. Returns true if listed.
func CheckRBL(ip net.IP, rblZone string) (bool, error) {
	ip4 := ip.To4()
	if ip4 == nil {
		return false, nil // Only IPv4 for standard DNSBL
	}

	// Reverse octets: 1.2.3.4 -> 4.3.2.1.zen.spamhaus.org
	queryHost := fmt.Sprintf("%d.%d.%d.%d.%s", ip4[3], ip4[2], ip4[1], ip4[0], rblZone)
	records, err := net.LookupHost(queryHost)
	if err != nil {
		// Non-existent domain (NXDOMAIN) means clean / not listed
		return false, nil
	}

	return len(records) > 0, nil
}
