# MailOpen Control Plane Roadmap

## W3.1 — Identity & Directory Layer (LDAP Integration) [COMPLETED]
- [x] Provider abstraction & models (`internal/identity/`)
- [x] Local PostgreSQL & Argon2id constant-time hashing
- [x] LDAP User Bind pattern & RFC 4515 filter escaping
- [x] Account Gatekeeper policy & Directory sync
- [x] Group to RBAC mapping (`admin`, `operator`, `auditor`, `user`)

---

## W3.2 — REST API Control Plane [COMPLETED]

### 1. API Architecture & Server Foundation
- [x] **Lightweight Stack**: Chi v5 Router, standard `net/http`, structured `slog`, Prometheus metrics
- [x] **Error Contract & Responses** (`internal/api/response/`): Standardized JSON error response with unique `request_id`, status code, details
- [x] **Middleware Suite** (`internal/api/middleware/`):
  - `RequestID`: `X-Request-ID` propagation & context injection
  - `Logging`: Structured HTTP request logging with duration and status code
  - `Recovery`: Panic recovery returning standard `INTERNAL_ERROR`
  - `Authenticate`: Opaque Bearer Token validation and claims extraction
  - `RequireRole`: RBAC permission gatekeeping
  - `RateLimit`: Sliding window rate limiter per client/user

### 2. Authentication & Token Management
- [x] **`internal/api/token/`**: Cryptographically secure opaque tokens (`mo_at_...`, `mo_rt_...`), SHA-256 database hashing, 15-min access token, 30-day refresh token with automatic one-time rotation and instant revocation.
- [x] **Endpoints**:
  - `POST /api/v1/auth/login` (multi-provider local & LDAP + gatekeeper check)
  - `POST /api/v1/auth/refresh` (single-use token rotation)
  - `POST /api/v1/auth/logout` (token revocation)
  - `GET /api/v1/auth/me` (authenticated identity profile)

### 3. Core Resource Endpoints
- [x] **Domains**: List, Create, Get, Delete, Doctor diagnostics, DNS record recommendations
- [x] **DKIM & TLS**: Key generation, selector verification, activation, revocation, TLS certificate inspection and installation
- [x] **Mailboxes**: Lifecycle management (`create`, `suspend`, `resume`, `provision`, `password`), Quota retrieval & reconciliation
- [x] **Aliases**: Create, list by destination, delete
- [x] **Identity & LDAP**: Provider status, doctor checks, LDAP directory sync
- [x] **Queue Management**: Queue summary status, message listing, inspect, retry, hold, release, flush, delete (admin only)
- [x] **Audit & Observability**: System audit logs (`/api/v1/audit`), Prometheus metrics (`/metrics`), Liveness/Readiness/Deep health probes (`/health/*`)

### 4. Specification & Verification
- [x] **OpenAPI 3.1 Spec**: Generated complete contract in `docs/api/openapi.yaml`
- [x] **Test Suite Matrix (`tests/api/api_test.go`)**: 100% PASS with race detector enabled (`go test -race`).
- [x] **Golden E2E Verification (`GOLDEN-API-001`)**: Full flow from Domain creation $\rightarrow$ DKIM setup $\rightarrow$ Mailbox provisioning $\rightarrow$ Token generation $\rightarrow$ User profile lookup $\rightarrow$ System doctor check.
