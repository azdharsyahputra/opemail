package dkim

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

// GenerateRSAKeyPair generates an RSA-2048 keypair formatted for DKIM.
func GenerateRSAKeyPair(bits int) (*Keypair, error) {
	if bits != 2048 {
		return nil, ErrInvalidKeyBits
	}

	privKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("failed to generate rsa key: %w", err)
	}

	privDER := x509.MarshalPKCS1PrivateKey(privKey)
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privDER,
	})

	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	})

	pubBase64 := base64.StdEncoding.EncodeToString(pubDER)

	return &Keypair{
		PrivateKeyPEM: privPEM,
		PublicKeyPEM:  pubPEM,
		PublicKeyDNS:  pubBase64,
	}, nil
}

// ParseRSAPrivateKey parses an RSA private key from PEM bytes (PKCS#1 or PKCS#8).
func ParseRSAPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM data")
	}

	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if rsaKey, ok := key.(*rsa.PrivateKey); ok {
			return rsaKey, nil
		}
	}

	return nil, fmt.Errorf("data is not a valid RSA private key")
}

// ParseRSAPublicKeyFromDNS parses the base64-encoded PKIX public key found in a DKIM DNS TXT record.
func ParseRSAPublicKeyFromDNS(base64Str string) (*rsa.PublicKey, error) {
	derBytes, err := base64.StdEncoding.DecodeString(base64Str)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 encoding: %w", err)
	}

	pubInterface, err := x509.ParsePKIXPublicKey(derBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKIX public key: %w", err)
	}

	rsaPub, ok := pubInterface.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not RSA")
	}

	return rsaPub, nil
}
