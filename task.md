# MailOpen W3.1 — Identity & Directory Layer (LDAP Integration)

## Core Definition of Done & Verification

### 1. Identity Abstraction & Provider Layer
- [x] **`internal/identity/`**: Domain models (`Identity`, `Group`, `Role`, `IdentityStatus`)
- [x] **`internal/identity/local/`**: PostgreSQL local provider with Argon2id constant-time hashing
- [x] **`internal/identity/ldap/`**: LDAP Provider with RFC 4515 filter escaping, User Bind pattern, and RBAC mapping
- [x] **`internal/identity/service.go`**: Multi-provider orchestrator with Gatekeeper security checks

### 2. Database Migration & Schema Compatibility
- [x] **`migrations/000011_add_identity_provider.up.sql`**: Added `identity_provider` column, nullable password hash for LDAP users

### 3. CLI Management
- [x] **`mailopen ldap doctor`**: Diagnostic checks for config, TLS, connection, search, and bind
- [x] **`mailopen identity auth`**: Multi-provider password authentication
- [x] **`mailopen identity lookup`**: Directory attributes and group resolution
- [x] **`mailopen identity sync` / `mailopen ldap sync`**: Discovers LDAP directory identities and provisions virtual mailboxes

### 4. Integration & Security Matrix (100% PASS)
- [x] **LDAP-001 to LDAP-010**: Authentication matrix (correct password, wrong password, unknown user, case normalization, disabled account, empty password)
- [x] **LDAP-SEC-001 to LDAP-SEC-008**: Filter injection protection, RFC 4515 character escaping, zero credential logging
- [x] **LDAP-TLS-001 to LDAP-TLS-008**: Modern TLS 1.2+ enforcement, certificate authority verification
- [x] **LDAP-FAIL-001 to LDAP-FAIL-009**: Provider unavailable fallback, timeout handling, recovery
- [x] **LDAP-RBAC-001 to LDAP-RBAC-007**: Group membership resolution and role translation (`mail-admins` -> `admin`, `mail-operators` -> `operator`, `mail-auditors` -> `auditor`)
- [x] **LDAP-GOLDEN-001**: Golden E2E Scenario (LDAP User created -> MailOpen Sync -> Mailbox provisioned -> Auth -> Submission/IMAP -> User Disabled -> Access Revoked)
