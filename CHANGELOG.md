# Changelog

All notable changes to the MailOpen project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.9.0] - 2026-08-21 (W2 General Availability Candidate)

### Added
- **Core Mail Transport (Postfix Adapter)**: Virtual mailbox domains, virtual mailbox maps, virtual alias maps, and sender login maps.
- **Mail Access & Authentication (Dovecot Adapter)**: IMAP (:143 with STARTTLS) and IMAPS (:993), Argon2id password hashing, and user authentication lifecycle (active, suspended, deleting).
- **SMTP Submission (:587)**: Mandatory STARTTLS, Dovecot SASL authentication, and anti-spoofing sender login mismatch protections.
- **DKIM Signing & Verification**: 2048-bit RSA key generation, dynamic selector activation, DNS TXT verification, and outbound OpenDKIM milter signing.
- **Inbound Security Pipeline**: SPF evaluation (RFC 7208), DKIM verification, DMARC evaluation (RFC 7489), and RFC 8601 `Authentication-Results` header generation.
- **Queue Management & Queue Doctor**: CLI commands for queue status, list, inspect, retry, hold, release, delete, and flush with Postfix spool driver.
- **Disaster Recovery & Encrypted Backups**: AES-256-GCM encrypted snapshot backups, integrity verification, and cross-host restoration with measured $\text{RPO} \le 15\text{m}$ and $\text{RTO} \le 30\text{m}$.
- **Comprehensive 10-Category System Doctor**: Live diagnostics covering Database, Transport, Mail Access, Security, Storage, Observability, Backups, Queues, and Certificates.
- **Automated Verification Suites**: Unit, Integration, Protocol compliance, Failure injection, Fuzz testing, Concurrency race detector, and 10 Golden E2E scenarios.

### Security
- Least-privilege PostgreSQL role boundaries (read-only for Dovecot and Postfix).
- Protection against SQL injection, path traversal, and malicious symlinks.
- Constant-time Argon2id password verification preventing timing analysis.
- Redaction of credentials, TLS keys, and DKIM private keys in all structured logs.
