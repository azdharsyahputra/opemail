# openmail

`openmail` is a modular, high-performance mail server management and control plane CLI built in Go, backed by PostgreSQL, Postfix inbound MTA (:25) & submission (:587), Dovecot SASL authentication, and Dovecot IMAP (:143) / IMAPS (:993) with TLS/STARTTLS hardening and native Maildir++ storage.

## Architecture

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

Client Configuration:
- **SMTP Submission**: `mail.example.com:587` | Security: `STARTTLS` (Mandatory) | Auth: `Required`
- **IMAP Secure**: `mail.example.com:993` | Security: `SSL/TLS` (IMAPS) | Auth: `Required`
- **IMAP Legacy/Compatible**: `mail.example.com:143` | Security: `STARTTLS` | Plaintext Auth: `BLOCKED`

See [docs/architecture.md](docs/architecture.md) and [task.md](task.md) for full architectural details.

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
go test -v ./...
```
