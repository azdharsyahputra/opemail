# openmail

`openmail` is a modular, high-performance mail server management and control plane CLI built in Go, backed by PostgreSQL, Postfix inbound MTA lookups, and Dovecot Maildir++ provisioning.

## Architecture

See [docs/architecture.md](docs/architecture.md) for full architectural details.

## Quick Start

### 1. Start Database
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
./bin/mailopen mailbox create ajar@example.com --password "secretPass123"

# List mailboxes with provisioning status
./bin/mailopen mailbox list

# Retry / Trigger idempotent provisioning
./bin/mailopen mailbox provision ajar@example.com

# Run mailbox doctor to verify filesystem & ownership health
./bin/mailopen mailbox doctor ajar@example.com

# Delete mailbox (deprovisions Maildir and removes from DB)
./bin/mailopen mailbox delete ajar@example.com
```

#### Postfix Adapter & MTA (W2.4)
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

# Reload Postfix service (only on config changes, not on mailbox changes)
./bin/mailopen postfix reload
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
