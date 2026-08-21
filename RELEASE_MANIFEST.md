# MailOpen Release Manifest

**Release Version**: `v0.9.0`  
**Git Commit**: `HEAD`  
**Build Date**: `2026-08-21`  
**Target Architectures**: `linux/amd64`, `linux/arm64`

## Component & Dependency Versions

| Component | Version | Verification Check |
|---|---|---|
| Go Compiler | `1.22.x+` | `-trimpath -ldflags="-s -w"` |
| PostgreSQL | `15.x / 16.x` | Port 5432 / Migrations 000001-000010 |
| Postfix | `3.7+` | MTA :25, Submission :587 |
| Dovecot | `2.3+` | IMAP :143, IMAPS :993, SASL |
| OpenDKIM | `2.11+` | RSA-2048 Milter |
| Rspamd | `3.7+` | Milter Scanning |
| ClamAV | `1.0+` | ClamD Milter Scanning |

## Go Module Dependencies
- `github.com/spf13/cobra` v1.8.0
- `github.com/lib/pq` v1.10.9
- `golang.org/x/crypto` v0.22.0
- `github.com/google/uuid` v1.6.0
- `github.com/golang-migrate/migrate/v4` v4.17.0
- `github.com/emersion/go-msgauth` v0.6.8
