package dkim

import (
	"crypto/rsa"
	"fmt"
	"strings"
)

// ValidatePrivateKey validates the syntax and format of the RSA private key PEM bytes.
func ValidatePrivateKey(privPEM []byte) (*rsa.PrivateKey, error) {
	privKey, err := ParseRSAPrivateKey(privPEM)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}

	if privKey.N.BitLen() != 2048 {
		return nil, ErrInvalidKeyBits
	}

	return privKey, nil
}

// ValidatePublicKeyMatch checks whether the given public key matches the given private key.
func ValidatePublicKeyMatch(privKey *rsa.PrivateKey, pubKey *rsa.PublicKey) bool {
	if privKey == nil || pubKey == nil {
		return false
	}
	return privKey.N.Cmp(pubKey.N) == 0 && privKey.E == pubKey.E
}

// ParseDNSTXTRecord parses a raw DNS TXT record value for DKIM and extracts tags.
func ParseDNSTXTRecord(txt string) (tags map[string]string, pubKeyStr string, err error) {
	txt = strings.TrimSpace(txt)
	// Remove outer quotes if present
	txt = strings.Trim(txt, "\"")

	tags = make(map[string]string)
	parts := strings.Split(txt, ";")

	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		kv := strings.SplitN(p, "=", 2)
		if len(kv) == 2 {
			k := strings.TrimSpace(strings.ToLower(kv[0]))
			v := strings.TrimSpace(kv[1])
			tags[k] = v
		}
	}

	v, ok := tags["v"]
	if !ok || strings.ToUpper(v) != "DKIM1" {
		return tags, "", fmt.Errorf("missing or invalid v tag (expected DKIM1)")
	}

	pVal, ok := tags["p"]
	if !ok || pVal == "" {
		return tags, "", fmt.Errorf("missing or empty p (public key) tag")
	}

	// Remove all whitespace from base64 string
	pClean := strings.ReplaceAll(pVal, " ", "")
	pClean = strings.ReplaceAll(pClean, "\t", "")
	pClean = strings.ReplaceAll(pClean, "\n", "")
	pClean = strings.ReplaceAll(pClean, "\r", "")

	return tags, pClean, nil
}
