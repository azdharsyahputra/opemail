# mailopen

`mailopen` is a modular, high-performance mail server management CLI built in Go and backed by PostgreSQL.

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

## Running Tests

```bash
go test -v ./...
```
