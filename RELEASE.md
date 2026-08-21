# MailOpen v0.9.0 Release Notes

MailOpen is a modern, modular, production-grade Mail Server Control Plane and Engine built in Go.

## Release Highlights
- **100% Tested Verification Plan**: Over 300 automated testcases across 5 verification levels (Unit, Integration, Protocol, Security & Abuse, Disaster Recovery & Concurrency).
- **Hardened Security**: Default fail-closed security model, zero open relay vulnerability on port 25, strict STARTTLS on submission 587, and Argon2id password hashing.
- **Enterprise Disaster Recovery**: Encrypted full-system backup snapshots with sub-second measured RTO on clean environments.
- **Standards Compliant**: Strict adherence to RFC 5321 (SMTP), RFC 3501 (IMAP4rev1), RFC 6409 (Submission), RFC 6376 (DKIM), RFC 7208 (SPF), RFC 7489 (DMARC), and RFC 8601 (Authentication-Results).

## Installation & Upgrade
Refer to the operational runbooks:
- [Installation Guide](docs/operations/installation.md)
- [Upgrade Guide](docs/operations/upgrade.md)
- [Disaster Recovery Guide](docs/operations/disaster-recovery.md)

## Release Binaries & Checksums
Release binaries are cross-compiled with `-trimpath` and `-ldflags="-s -w"`:
- `dist/mailopen-linux-amd64`
- `dist/mailopen-linux-arm64`
- `dist/SHA256SUMS`
