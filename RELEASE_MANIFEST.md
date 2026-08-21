# MailOpen Release Manifest

**Release Version**: `v0.9.0`  
**Git Tag**: `v0.9.0`  
**Git Commit**: `9589ae253d5e37d379b5bb141625b0e9199fea6e`  
**Build Environment**: `Go 1.26.4 (darwin/arm64 -> linux/amd64, linux/arm64)`  
**Build Flags**: `CGO_ENABLED=0 -trimpath -ldflags="-s -w"`  
**Database Schema Migration**: `000010` (Sequential 000001 - 000010)

---

## 1. Distribution Artifacts & SHA256 Checksums

```text
940dffd76afb9c8773b9b3abc916c8ed180732f465a310512ea0098851e7d8b2  mailopen-linux-amd64
88571a600abe4bdfc4794960d082bb2a038bfcc47fa6457da8b174f5024376dd  mailopen-linux-arm64
```

---

## 2. Component & Subsystem Versions

| Component | Target Version | Interface & Capabilities |
|---|---|---|
| PostgreSQL | `15.x / 16.x` | TCP :5432 / Migrations 000001-000010 / Least-privilege roles |
| Postfix | `3.7+` | MTA :25, Submission :587, Milter OpenDKIM |
| Dovecot | `2.3+` | IMAP :143 STARTTLS, IMAPS :993, SASL Auth |
| OpenDKIM | `2.11+` | RSA-2048 Milter Outbound Signing |
| Rspamd | `3.7+` | Inbound spam scoring & Milter pipeline |
| ClamAV | `1.0+` | ClamD malware scanning |

---

## 3. Security Hardening Controls

- **Transport Security**: Minimum TLS 1.2 enforced on :25, :587, :143, :993 (legacy TLS 1.0 & 1.1 blocked).
- **Authentication**: Argon2id ($m=65536, t=3, p=4$) with constant-time verification.
- **Relay Policy**: Zero open relay on :25 (`554 Relay access denied`); Outbound relay permitted exclusively via authenticated Submission :587.
- **Identity & Spoofing Defense**: OpenDKIM RSA-2048 signing, RFC 7208 SPF evaluation, RFC 7489 DMARC alignment, and RFC 8601 `Authentication-Results` generation.
- **Database Boundary**: PostgreSQL least-privilege `SELECT`-only permissions for Dovecot and Postfix accounts.
- **Data Protection**: AES-256-GCM encrypted snapshot backups with sub-minute disaster recovery.

---

## 4. Verification Suite Results

- **Static Analysis (vet + staticcheck)**: `PASS` (0 warnings, 0 findings)
- **Race Detection (`go test -race`)**: `PASS` (0 data races)
- **Unit Tests**: `PASS`
- **Integration Tests**: `PASS`
- **Protocol Tests (SMTP, Submission, IMAP, TLS)**: `PASS`
- **Security Tests (SQLi, Path Traversal, Secrets Audit)**: `PASS`
- **Failure & Recovery Injection**: `PASS`
- **Native Fuzz Tests**: `PASS`
- **Concurrency & Quota Race**: `PASS`
- **10 Golden E2E Scenarios**: `PASS`
- **15 Final Production GA Gates (W2-GA-001 to W2-GA-015)**: `15/15 PASS`

---

## 5. Architectural Boundary: W2 Core vs W3 Control Plane

```text
                    MAILOPEN
                       │
          ┌────────────┴────────────┐
          │                         │
       W2 CORE                   W3
     (FROZEN GA)            CONTROL PLANE
          │                         │
     Postfix                   REST API
     Dovecot                   Web Admin UI
     TLS / Certs               Auth / RBAC
     DKIM / SPF / DMARC        Domain API
     Rspamd / ClamAV           Mailbox API
     Mail Queue                Queue UI
     Storage Quota             Metrics Dashboard
     Backup & DR               Audit Logs UI
```
