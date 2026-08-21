# openmail

`openmail` is a modular, high-performance mail server management and control plane CLI built in Go, backed by PostgreSQL and pluggable Blob Storage.

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

#### Mailbox Management
```bash
# Create mailbox
./bin/mailopen mailbox create ajar@example.com --password "secretPass123"

# List mailboxes
./bin/mailopen mailbox list

# Delete mailbox
./bin/mailopen mailbox delete ajar@example.com
```

#### Message Management (Week 2)
```bash
# Store raw email into mailbox
cat email.eml | ./bin/mailopen message store ajar@example.com

# List messages in mailbox
./bin/mailopen message list ajar@example.com

# Get message details and raw payload
./bin/mailopen message get <message-uuid>

# Delete message
./bin/mailopen message delete <message-uuid>
```

## Running Tests

```bash
go test -v ./...
```
