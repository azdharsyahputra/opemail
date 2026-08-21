# W2.7 — TLS / STARTTLS + Secure Mail Access

## 0. Target Architecture

```text
                         INTERNET
                            │
             ┌──────────────┴──────────────┐
             │                             │
           TCP :25                       TCP :587
             │                             │
        SMTP / MTA                    Submission
             │                             │
        STARTTLS opt.                 STARTTLS (REQUIRED)
             │                             │
             └──────────────┬──────────────┘
                            │
                           TLS
                            │
                         Postfix
                            │
                       Dovecot SASL
                            │
                       PostgreSQL


                         TCP :993                   TCP :143
                            │                          │
                        IMAPS (TLS)                 STARTTLS
                            │                          │
                            └───────────┬──────────────┘
                                        │
                                     Dovecot
                                        │
                                   PostgreSQL
```

Client configuration:
```text
SMTP Submission:
  host: mail.example.com
  port: 587
  security: STARTTLS
  auth: required

IMAP:
  host: mail.example.com
  port: 993 (IMAPS) / 143 (STARTTLS)
  security: SSL/TLS / STARTTLS
  auth: required (plaintext auth blocked before TLS)
```

---

## 1. Definition of Done Checklist

- [ ] **TLS Abstraction & Validation (`internal/tls`)**
  - [ ] Model `Certificate` and `CertificateReport`
  - [ ] PEM x509 parser & Private key parser (RSA/ECDSA/Ed25519)
  - [ ] Public key / Private key match verification
  - [ ] SAN Hostname validation (`cert.VerifyHostname`)
  - [ ] Expiration validation (>30d HEALTHY, 8-30d WARNING, 1-7d CRITICAL, <=0d EXPIRED)
  - [ ] Filesystem provider (`/etc/mailopen/tls/<hostname>/`)
  - [ ] Atomic certificate installation (`.tmp` -> `fsync` -> `chmod` -> `rename`)
  - [ ] Permissions (`0750` dir, `0644` fullchain.pem, `0600` privkey.pem)
  - [ ] Safety rollback (invalid cert never replaces active cert)
- [ ] **Postfix TLS Hardening**
  - [ ] Port 25: STARTTLS offered (`may`), SMTP AUTH DISABLED
  - [ ] Port 587: STARTTLS required (`encrypt`), SMTP AUTH required
  - [ ] Plaintext AUTH before TLS rejected on :587
  - [ ] Protocols: TLSv1.2 & TLSv1.3 enabled, TLSv1.0 & TLSv1.1 disabled
- [ ] **Dovecot TLS Hardening**
  - [ ] Port 993: Implicit TLS (IMAPS)
  - [ ] Port 143: STARTTLS enabled, plaintext auth before TLS blocked (`ssl = required`)
  - [ ] Protocols: `ssl_min_protocol = TLSv1.2`
  - [ ] Certificate & key paths configured
- [ ] **CLI Subcommands**
  - [ ] `mailopen tls install --hostname <host> --cert <cert> --key <key>`
  - [ ] `mailopen tls validate --hostname <host>`
  - [ ] `mailopen tls status --hostname <host>`
  - [ ] `mailopen tls doctor --hostname <host>`
- [ ] **Testing & Diagnostics**
  - [ ] Unit tests for cert/key matching, expiration, hostname verification
  - [ ] `tests/tls_integration_test.go` real socket testing:
    - [ ] Certificate valid / expired / mismatch / wrong hostname
    - [ ] TLS 1.2 / 1.3 / 1.0 blocked / 1.1 blocked
    - [ ] Port 587: STARTTLS + AUTH after TLS works, AUTH before TLS fails
    - [ ] Port 25: STARTTLS works, AUTH fails
    - [ ] Port 993: IMAPS TLS connect + LOGIN works
    - [ ] Port 143: LOGIN before STARTTLS fails, LOGIN after STARTTLS works
    - [ ] Full E2E mail submission (:587 STARTTLS) -> local delivery -> IMAPS (:993 TLS fetch)
