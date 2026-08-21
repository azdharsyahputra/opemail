# Mailopen Architecture (Week 1)

## High-Level Diagram

```text
                    CLI (Cobra)
                         │
                         ▼
                  Application Core
                         │
          ┌──────────────┴──────────────┐
          ▼                             ▼
    Domain Service               Mailbox Service
          │                             │
          └──────────────┬──────────────┘
                         ▼
                     PostgreSQL
```

## Layer Description

1. **CLI Layer (`internal/cli`)**: Parses command line flags and subcommands via Cobra (`mailopen domain ...`, `mailopen mailbox ...`).
2. **Service Layer (`internal/domain`, `internal/mailbox`)**: Enforces business logic rules (email parsing, domain resolution, password hashing with Argon2id, uniqueness checks, format validation).
3. **Repository Layer**: Abstraction interface over the data storage (`Repository` interface). Allows swapping PostgreSQL for mock/in-memory implementations during testing.
4. **Database & Migration (`internal/database`, `migrations`)**: Connection pooling and embedded SQL migrations via `golang-migrate`.
