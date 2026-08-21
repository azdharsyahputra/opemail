# W2.9 — Inbound Mail Security & Anti-Abuse

## 0. Target Architecture

```text
                         INTERNET
                            │
                            │ TCP :25
                            ▼
                  ┌──────────────────┐
                  │     Postfix      │
                  │   SMTP Receive   │
                  └─────────┬────────┘
                            │
                            ├── Connection controls (:25 limits)
                            ├── HELO/EHLO validation
                            ├── Client & Recipient validation (PostgreSQL)
                            ├── Rate limiting & Anti-abuse controls
                            ├── RBL / DNSBL & Reverse DNS (PTR/FCrDNS)
                            ├── SPF evaluation (RFC 7208)
                            ├── DKIM verification (RFC 6376)
                            └── DMARC evaluation & alignment (RFC 7489)
                            │
                            ▼
                  ┌──────────────────┐
                  │ Content Pipeline │
                  └─────────┬────────┘
                            │
                            ├── Spam evaluation (Rspamd / scoring)
                            ├── Antivirus scanning (ClamAV / malware)
                            ├── Header injection (Authentication-Results, Received-SPF)
                            ├── Oversized message rejection (message_size_limit)
                            ├── Quarantine / Junk routing
                            │
                            ▼
                       Maildir/new/
                            │
                            ▼
                         Dovecot
```

Control Plane vs Data Plane:
- **Control Plane (MailOpen)**: Policy configurations, thresholds, mailbox limits, diagnostic doctors.
- **Data Plane (Postfix, Dovecot, OpenDKIM, Rspamd, ClamAV)**: Real-time network and mail processing.
- **Runtime State**: Dynamic lookups and memory counters (Redis / in-memory rate limiters).
- **Secrets & Storage**: Filesystem Maildir, TLS certs, DKIM private keys.

---

## 1. Definition of Done Checklist

- [ ] **W2.9.1 Database Migrations for Mail Policy & Mailbox Limits**
  - [ ] Migration `000007_mail_policy.up.sql` (spam_threshold, reject_threshold, quarantine, size_limit, rbl_policy)
  - [ ] Migration `000008_mailbox_limits.up.sql` (outbound rate limits per mailbox)
  - [ ] Models & PostgreSQL repositories
- [ ] **W2.9.2 Inbound Security & Policy Engine (`internal/inbound/`)**
  - [ ] Recipient validation without enumeration leakage (unknown & suspended both return consistent 550)
  - [ ] HELO/EHLO validation & Postfix connection controls
  - [ ] SPF inbound evaluation (pass, fail, softfail, neutral, none, temperror, permerror)
  - [ ] DKIM inbound verification (pass, fail, none, neutral)
  - [ ] DMARC alignment evaluation (SPF aligned OR DKIM aligned)
  - [ ] DMARC policy enforcement (none, quarantine, reject)
  - [ ] Header generation & injection (`Authentication-Results:`, `Received-SPF:`)
  - [ ] Reverse DNS & RBL reputation policies
- [ ] **W2.9.3 Spam & Antivirus Pipelines (`internal/spam/`, `internal/antivirus/`)**
  - [ ] Spam scoring thresholds & quarantine policy
  - [ ] Antivirus scanner integration & malware detection
  - [ ] Message size limit enforcement
- [ ] **W2.9.4 Abuse & Rate Limiting Engine (`internal/abuse/`)**
  - [ ] Outbound authenticated user limits (messages/min, messages/hr, recipients/day)
  - [ ] IP connection burst & rate limit tracking
- [ ] **W2.9.5 Postfix & Milter Inbound Hardening**
  - [ ] Postfix `main.cf`: connection, message, recipient rate limits, `message_size_limit`, HELO restrictions
- [ ] **W2.9.6 CLI Subcommands**
  - [ ] `mailopen inbound doctor`
  - [ ] `mailopen inbound policy show / set <domain>`
  - [ ] `mailopen inbound test smtp / spf / dkim / dmarc`
  - [ ] `mailopen spam status / doctor`
  - [ ] `mailopen antivirus status / doctor`
  - [ ] `mailopen abuse status / limits show / limits set`
  - [ ] `mailopen domain doctor <domain>` (full comprehensive 24-point check)
- [ ] **W2.9.7 Test Matrices & Full Integration**
  - [ ] Inbound recipient validation test
  - [ ] SMTP connection limit test
  - [ ] SPF inbound evaluation test matrix
  - [ ] DKIM inbound verification test matrix
  - [ ] DMARC alignment & policy test matrix
  - [ ] Spam & antivirus detection test matrix
  - [ ] Outbound abuse rate limit test
  - [ ] Regression test across W2.1 - W2.9 (`go test -count=1 -v ./...`)
