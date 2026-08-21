# MailOpen W2 — Final GA Gate (W2-GA-001 to W2-GA-015)

## 15 Final Production GA Gates
- [x] **W2-GA-001**: Clean-room bootstrap & installation validation (`mailopen system doctor` -> HEALTHY)
- [x] **W2-GA-002**: Fresh install real email flow (Inbound, Outbound, Local delivery, IMAP state)
- [x] **W2-GA-003**: Real public DNS validation (A, AAAA, MX, PTR, FCrDNS, SPF, DKIM, DMARC)
- [x] **W2-GA-004**: External deliverability contract (RFC 8601 Authentication-Results, SPF pass, DKIM pass, DMARC pass)
- [x] **W2-GA-005**: External inbound abuse controls (550 reject on unknown recipient, 250 accept on valid, AUTH on :25 blocked)
- [x] **W2-GA-006**: Open relay final prohibition (Internet :25 -> victim@gmail.com MUST return 554 Relay access denied; :587 + valid AUTH -> 250 queued)
- [x] **W2-GA-007**: TLS external scanning (TLS 1.2 & 1.3 accepted, legacy TLS 1.0 & 1.1 rejected)
- [x] **W2-GA-008**: Full Account & Password lifecycle (Create -> Auth -> Pass Change -> Old Fails -> New Passes -> Suspend -> Auth Fails -> Resume -> Auth Passes -> Delete -> Auth Fails)
- [x] **W2-GA-009**: Data persistence across system, database, and MTA restarts
- [x] **W2-GA-010**: Upgrade validation from release artifact binary
- [x] **W2-GA-011**: Backup portability & cross-host disaster recovery
- [x] **W2-GA-012**: Secret & credential audit across git history, logs, and binaries
- [x] **W2-GA-013**: Container & dependency vulnerability security audit (0 critical)
- [x] **W2-GA-014**: Dependency freeze, Release Manifest & CycloneDX SBOM
- [x] **W2-GA-015**: Final GA release artifact build from `v0.9.0` tag (`dist/SHA256SUMS`, `CHANGELOG.md`, `RELEASE.md`)
