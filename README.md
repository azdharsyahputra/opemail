# openmail

`openmail` is a modular, high-performance mail server management and control plane CLI built in Go, backed by PostgreSQL, Postfix inbound MTA (:25) & submission (:587), OpenDKIM milter signing, Dovecot SASL authentication, Dovecot IMAP (:143) / IMAPS (:993) with TLS/STARTTLS hardening, Inbound Security, Spam/Antivirus filtering, Outbound submission rate limits, and native Maildir++ storage.

## Architecture

```text
                         INTERNET
                            │
             ┌──────────────┴──────────────┐
             │                             │
          INBOUND                       OUTBOUND
             │                             │
             ▼                             ▼
        Postfix :25                  Postfix :587
             │                             │
             ├── Connection Controls       ├── STARTTLS (Mandatory)
             ├── HELO/EHLO Validation      ├── SMTP AUTH (Dovecot SASL)
             ├── Recipient Validation      ├── Outbound Rate Limits
             ├── SPF Inbound Evaluation    │
             ├── DKIM Inbound Verification ▼
             ├── DMARC Alignment Check  OpenDKIM Milter Signing
             │                             │
             ▼                             ▼
        Rspamd & ClamAV                 Internet
        (Spam & Antivirus)
             │
             ├── Header Injection
             │   (Authentication-Results, Received-SPF)
             ├── Quarantine / Junk
             │
             ▼
        Maildir/new/
             │
             ▼
          Dovecot
```

Client Configuration:
- **SMTP Submission**: `mail.example.com:587` | Security: `STARTTLS` (Mandatory) | Auth: `Required` | Outbound: `DKIM Signed`
- **IMAP Secure**: `mail.example.com:993` | Security: `SSL/TLS` (IMAPS) | Auth: `Required`
- **IMAP Legacy/Compatible**: `mail.example.com:143` | Security: `STARTTLS` | Plaintext Auth: `BLOCKED`

See [docs/architecture.md](docs/architecture.md), [docs/deliverability.md](docs/deliverability.md), and [task.md](task.md) for full architectural details.

## Quick Start

### 1. Start Database & Mail Services Stack
```bash
docker compose -f deploy/docker-compose.yml up -d
```

### 2. Build CLI
```bash
go build -o bin/mailopen ./cmd/mailopen
```

### 3. Run Database Migrations
```bash
./bin/mailopen migrate up
```

### 4. CLI Usage Examples

#### Inbound Mail Security & Abuse Controls (W2.9)
```bash
# Run comprehensive Inbound Security Doctor
./bin/mailopen inbound doctor

# Simulate real-time inbound SPF evaluation
./bin/mailopen inbound test spf 203.0.113.10 sender.com "v=spf1 ip4:203.0.113.10 -all"

# Simulate real-time inbound DMARC alignment & policy verdict
./bin/mailopen inbound test dmarc user@example.com pass example.com fail evil.com reject

# Check Spam filtering (Rspamd) engine status & thresholds
./bin/mailopen spam status
./bin/mailopen spam doctor

# Check Antivirus scanning (ClamAV) engine status
./bin/mailopen antivirus status
./bin/mailopen antivirus doctor

# Check abuse protection status & manage mailbox submission rate limits
./bin/mailopen abuse status
./bin/mailopen abuse limits show ajar@example.com
./bin/mailopen abuse limits set ajar@example.com --msgs-per-min 20 --msgs-per-hour 200 --rcpt-per-day 800
```

#### Mail Identity, DKIM, SPF & DMARC (W2.8)
```bash
# Generate RSA-2048 DKIM key and prepare DNS TXT record
./bin/mailopen dkim key generate example.com --selector mailopen2026

# List all DKIM keys and statuses for a domain
./bin/mailopen dkim key list example.com

# Verify DKIM DNS record publication against local private key
./bin/mailopen dkim verify example.com --selector mailopen2026

# Activate DKIM key for live outbound email signing
./bin/mailopen dkim key activate example.com mailopen2026

# Revoke DKIM key
./bin/mailopen dkim key revoke example.com mailopen2026

# Run comprehensive DKIM Doctor diagnostics
./bin/mailopen dkim doctor example.com

# Manage SPF policies
./bin/mailopen domain spf show example.com
./bin/mailopen domain spf set example.com --policy "v=spf1 mx ip4:203.0.113.10 -all"
./bin/mailopen domain spf verify example.com

# Manage DMARC policies
./bin/mailopen domain dmarc show example.com
./bin/mailopen domain dmarc set example.com --policy "v=DMARC1; p=none; rua=mailto:dmarc@example.com"
./bin/mailopen domain dmarc verify example.com

# Run full Mail Domain Doctor (MX, A, SPF, DKIM, DMARC, TLS, SMTP, IMAP)
./bin/mailopen domain doctor example.com

# Generate OpenDKIM milter configuration and check socket status
./bin/mailopen postfix dkim generate
./bin/mailopen postfix dkim status
```

#### TLS / STARTTLS Certificate Management (W2.7)
```bash
# Atomically validate and install certificate & private key
./bin/mailopen tls install --hostname mail.example.com --cert /path/to/fullchain.pem --key /path/to/privkey.pem

# Validate installed certificate on filesystem
./bin/mailopen tls validate --hostname mail.example.com

# Check certificate status & remaining expiration days
./bin/mailopen tls status --hostname mail.example.com

# Run full TLS Doctor diagnostics across certs, Postfix, and Dovecot
./bin/mailopen tls doctor --hostname mail.example.com
```

#### Domain Management
```bash
# Create domain
./bin/mailopen domain create example.com

# List domains
./bin/mailopen domain list
```

#### Mailbox Management & Provisioning (W2.3)
```bash
# Create mailbox (auto-provisions Dovecot Maildir++)
./bin/mailopen mailbox create ajar@example.com --password "SecurePass123"

# Update password (dynamic instant auth, zero reloads needed)
./bin/mailopen mailbox password set ajar@example.com --password "NewPass123"

# List mailboxes with provisioning status
./bin/mailopen mailbox list

# Retry / Trigger idempotent provisioning
./bin/mailopen mailbox provision ajar@example.com

# Run mailbox doctor to verify filesystem & ownership health
./bin/mailopen mailbox doctor ajar@example.com

# Delete mailbox (deprovisions Maildir and removes from DB)
./bin/mailopen mailbox delete ajar@example.com
```

#### Postfix Inbound MTA (W2.4)
```bash
# Generate Postfix configuration and pgsql maps
./bin/mailopen postfix config generate

# Validate Postfix configuration syntax
./bin/mailopen postfix config validate

# Run Postfix Doctor diagnostics & live database lookup checks
./bin/mailopen postfix doctor

# Test dynamic PostgreSQL lookups
./bin/mailopen postfix lookup domain example.com
./bin/mailopen postfix lookup mailbox ajar@example.com
./bin/mailopen postfix lookup alias support@example.com

# Reload Postfix service (only on config changes)
./bin/mailopen postfix reload
```

#### Postfix Submission & SMTP AUTH (W2.6)
```bash
# Generate Postfix submission configuration (:587 + Dovecot SASL)
./bin/mailopen postfix submission config generate

# Validate Postfix submission configuration
./bin/mailopen postfix submission config validate

# Run Postfix Submission Doctor diagnostics
./bin/mailopen postfix submission doctor

# Check Submission service listener status (:587)
./bin/mailopen postfix submission status

# Test SMTP AUTH against Dovecot SASL & PostgreSQL (passwords never logged)
./bin/mailopen postfix submission auth-test ajar@example.com --password "SecurePass123"
```

#### Dovecot IMAP & Authentication Adapter (W2.5)
```bash
# Generate Dovecot configuration and SQL mapping files
./bin/mailopen dovecot config generate

# Validate Dovecot configuration syntax
./bin/mailopen dovecot config validate

# Run Dovecot Doctor diagnostics & health check
./bin/mailopen dovecot doctor

# Simulate userdb lookup (derived Maildir path)
./bin/mailopen dovecot lookup user ajar@example.com

# Test Argon2id passdb authentication against PostgreSQL
./bin/mailopen dovecot auth test ajar@example.com --password "SecurePass123"

# Reload Dovecot service (only on config changes)
./bin/mailopen dovecot reload
```

#### Storage & Message Management
```bash
# Store raw email into mailbox
cat email.eml | ./bin/mailopen message store ajar@example.com

# List messages in mailbox
./bin/mailopen message list ajar@example.com

# Get message details and raw payload
./bin/mailopen message get <message-uuid>

# Run Garbage Collector for orphaned blobs
./bin/mailopen storage gc --dry-run
./bin/mailopen storage gc
```

## Running Tests

```bash
DATABASE_URL="postgres://mailopen:mailopen@localhost:5433/mailopen?sslmode=disable" go test -count=1 -v ./...
```
