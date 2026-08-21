package api_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/azdharsyahputra/openmail/internal/api"
	"github.com/azdharsyahputra/openmail/internal/api/handler"
	"github.com/azdharsyahputra/openmail/internal/api/token"
	"github.com/azdharsyahputra/openmail/internal/audit"
	"github.com/azdharsyahputra/openmail/internal/config"
	"github.com/azdharsyahputra/openmail/internal/database"
	"github.com/azdharsyahputra/openmail/internal/dkim"
	"github.com/azdharsyahputra/openmail/internal/domain"
	"github.com/azdharsyahputra/openmail/internal/identity"
	"github.com/azdharsyahputra/openmail/internal/identity/ldap"
	"github.com/azdharsyahputra/openmail/internal/identity/local"
	"github.com/azdharsyahputra/openmail/internal/mailbox"
	"github.com/azdharsyahputra/openmail/internal/metrics"
	"github.com/azdharsyahputra/openmail/internal/provisioning"
	"github.com/azdharsyahputra/openmail/internal/queue"
	"github.com/azdharsyahputra/openmail/internal/quota"
	openmailtls "github.com/azdharsyahputra/openmail/internal/tls"
	goldap "github.com/go-ldap/ldap/v3"
)


type apiTestRig struct {
	db         *sql.DB
	server     *httptest.Server
	client     *http.Client
	domSvc     domain.Service
	mbSvc      mailbox.Service
	identSvc   identity.Service
	tokenMgr   token.Manager
	adminToken string
	operToken  string
	auditToken string
	userToken  string
}

func setupAPITestRig(t *testing.T) *apiTestRig {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		cfg, err := config.Load()
		if err == nil && cfg.DatabaseURL != "" {
			dbURL = cfg.DatabaseURL
		} else {
			dbURL = "postgres://mailopen:mailopen@localhost:5433/mailopen?sslmode=disable"
		}
	}
	db, err := database.NewPostgresDB(dbURL)
	if err != nil {
		t.Skipf("Skipping test: PostgreSQL unavailable (%v)", err)
		return nil
	}
	if err := database.RunMigrationsUp(db); err != nil {
		t.Fatalf("failed to run migrations: %v", err)
	}

	tempVmail := t.TempDir()
	tempTLS := t.TempDir()
	tempDKIM := t.TempDir()

	domRepo := domain.NewPostgresRepository(db)
	mbRepo := mailbox.NewPostgresRepository(db)
	aliasRepo := mailbox.NewAliasRepository(db)
	tokenRepo := token.NewPostgresRepository(db)
	auditRepo := audit.NewPostgresRepository(db)
	dkimRepo := dkim.NewPostgresRepository(db)

	prov, _ := provisioning.NewFilesystemProvisioner(tempVmail, os.Getuid(), os.Getgid())
	mbSvc := mailbox.NewService(mbRepo, domRepo, prov)
	domSvc := domain.NewService(domRepo)
	tokenMgr := token.NewManager(tokenRepo)
	auditSvc := audit.NewService(auditRepo)
	qSvc := queue.NewService(queue.NewSystemDriver("mailopen_postfix"))
	quotaSvc := quota.NewService(mbRepo, prov)

	keystore := dkim.NewFilesystemKeystore(tempDKIM)
	dkimSvc := dkim.NewService(dkimRepo, domRepo, keystore)
	tlsProv := openmailtls.NewFilesystemProvider(tempTLS)
	tlsSvc := openmailtls.NewService(tlsProv)

	localProv := local.NewProvider(mbRepo)
	mockClient := &mockAPILDAPClient{
		entries: map[string]*goldap.Entry{
			"uid=ldapadmin,ou=people,dc=example,dc=com": {
				DN: "uid=ldapadmin,ou=people,dc=example,dc=com",
				Attributes: []*goldap.EntryAttribute{
					{Name: "uid", Values: []string{"ldapadmin"}},
					{Name: "mail", Values: []string{"ldapadmin@example.com"}},
					{Name: "cn", Values: []string{"LDAP Admin"}},
					{Name: "memberOf", Values: []string{"cn=mail-admins,ou=groups,dc=example,dc=com"}},
				},
			},
		},
		passwords: map[string]string{
			"uid=ldapadmin,ou=people,dc=example,dc=com": "AdminPass123!",
		},
	}
	ldapProv := ldap.NewProvider(ldap.DefaultConfig(), mockClient)
	providers := map[string]identity.IdentityProvider{
		"local": localProv,
		"ldap":  ldapProv,
	}
	identSvc := identity.NewService("local", providers, mbRepo, domRepo, mbSvc)

	healthH := handler.NewHealthHandler(db, qSvc, tempVmail, tempTLS, tempDKIM)
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))

	router := api.NewRouter(api.RouterDependencies{
		Logger:          logger,
		TokenManager:    tokenMgr,
		IdentityService: identSvc,
		DomainService:   domSvc,
		MailboxService:  mbSvc,
		QuotaService:    quotaSvc,
		AliasRepo:       aliasRepo,
		MailboxRepo:     mbRepo,
		DomainRepo:      domRepo,
		DKIMService:     dkimSvc,
		TLSService:      tlsSvc,
		QueueService:    qSvc,
		AuditService:    auditSvc,
		HealthHandler:   healthH,
		MetricsRegistry: metrics.DefaultRegistry,
	})


	ts := httptest.NewServer(router)

	// Issue Tokens for RBAC testing
	ctx := context.Background()
	adminPair, _ := tokenMgr.IssueTokenPair(ctx, nil, "admin@example.com", "admin")
	operPair, _ := tokenMgr.IssueTokenPair(ctx, nil, "operator@example.com", "operator")
	auditPair, _ := tokenMgr.IssueTokenPair(ctx, nil, "auditor@example.com", "auditor")
	userPair, _ := tokenMgr.IssueTokenPair(ctx, nil, "user@example.com", "user")

	return &apiTestRig{
		db:         db,
		server:     ts,
		client:     ts.Client(),
		domSvc:     domSvc,
		mbSvc:      mbSvc,
		identSvc:   identSvc,
		tokenMgr:   tokenMgr,
		adminToken: adminPair.AccessToken,
		operToken:  operPair.AccessToken,
		auditToken: auditPair.AccessToken,
		userToken:  userPair.AccessToken,
	}
}

type mockAPILDAPClient struct {
	entries   map[string]*goldap.Entry
	passwords map[string]string
}

func (m *mockAPILDAPClient) Search(ctx context.Context, baseDN, filter string, scope int, attributes []string) ([]*goldap.Entry, error) {
	var results []*goldap.Entry
	for _, e := range m.entries {
		results = append(results, e)
	}
	return results, nil
}
func (m *mockAPILDAPClient) Bind(ctx context.Context, dn, password string) error { return nil }
func (m *mockAPILDAPClient) AuthenticateUser(ctx context.Context, userDN, password string) error {
	if expected, ok := m.passwords[userDN]; ok && expected == password {
		return nil
	}
	return identity.ErrAuthenticationFailed
}
func (m *mockAPILDAPClient) PasswordModify(ctx context.Context, userDN, oldPassword, newPassword string) error {
	return nil
}
func (m *mockAPILDAPClient) Close() error { return nil }

func (r *apiTestRig) doRequest(method, path, token string, body interface{}) (*http.Response, []byte, error) {
	var reqBody io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		reqBody = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, r.server.URL+path, reqBody)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	return resp, respBytes, err
}

// 1. API PROTOCOL & OBSERVABILITY (API-001 to API-010)
func TestREST_API_ProtocolAndObservability(t *testing.T) {
	rig := setupAPITestRig(t)
	if rig == nil {
		return
	}
	defer rig.server.Close()
	defer rig.db.Close()

	t.Run("API-001: Health Live & Ready Endpoints", func(t *testing.T) {
		resp, body, err := rig.doRequest("GET", "/health/live", "", nil)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Errorf("health live failed: code=%d, err=%v, body=%s", resp.StatusCode, err, string(body))
		}

		resp, _, err = rig.doRequest("GET", "/health/ready", "", nil)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Errorf("health ready failed: code=%d, err=%v", resp.StatusCode, err)
		}

		respDeep, _, err := rig.doRequest("GET", "/health/deep", "", nil)
		if err != nil || respDeep.StatusCode != http.StatusOK {
			t.Errorf("health deep failed: code=%d, err=%v", respDeep.StatusCode, err)
		}
	})

	t.Run("API-002: Malformed JSON Request Payload", func(t *testing.T) {
		req, _ := http.NewRequest("POST", rig.server.URL+"/api/v1/auth/login", strings.NewReader("{invalid-json"))
		req.Header.Set("Content-Type", "application/json")
		resp, _ := rig.client.Do(req)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("expected 400 Bad Request on malformed JSON, got: %d", resp.StatusCode)
		}
	})

	t.Run("API-003: Metrics Rendering (Prometheus format)", func(t *testing.T) {
		resp, body, err := rig.doRequest("GET", "/metrics", "", nil)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("metrics endpoint failed: %d", resp.StatusCode)
		}
		if !strings.Contains(string(body), "smtp_connections_total") {
			t.Errorf("expected prometheus metrics format, got: %s", string(body))
		}
	})

	t.Run("API-004: Unknown Route (404 Not Found)", func(t *testing.T) {
		resp, _, err := rig.doRequest("GET", "/api/v1/nonexistent-endpoint", rig.adminToken, nil)
		if err != nil || resp.StatusCode != http.StatusNotFound {
			t.Errorf("expected 404 for unknown route, got: %d", resp.StatusCode)
		}
	})

	t.Run("API-010: Request ID Propagation Header", func(t *testing.T) {
		resp, _, _ := rig.doRequest("GET", "/health/live", "", nil)
		reqID := resp.Header.Get("X-Request-ID")
		if reqID == "" {
			t.Errorf("expected X-Request-ID header in response")
		}
	})
}

// 2. AUTHENTICATION & TOKEN LIFECYCLE (AUTH-API-001 to AUTH-API-010)
func TestREST_API_Authentication(t *testing.T) {
	rig := setupAPITestRig(t)
	if rig == nil {
		return
	}
	defer rig.server.Close()
	defer rig.db.Close()

	ctx := context.Background()
	testDom := fmt.Sprintf("auth-api-%d.com", time.Now().UnixNano())
	_, _ = rig.domSvc.Create(ctx, testDom)
	defer rig.domSvc.Delete(ctx, testDom)

	userEmail := "login-user@" + testDom
	userPass := "SecretPass123!"
	mb, _ := rig.mbSvc.Create(ctx, userEmail, userPass, 1073741824)
	_, _, _ = rig.mbSvc.Provision(ctx, userEmail)

	t.Run("AUTH-API-001: Valid Login -> Issue Access & Refresh Tokens", func(t *testing.T) {
		resp, body, err := rig.doRequest("POST", "/api/v1/auth/login", "", map[string]string{
			"username": userEmail,
			"password": userPass,
		})
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("login failed: %d, body: %s", resp.StatusCode, string(body))
		}

		var payload map[string]interface{}
		_ = json.Unmarshal(body, &payload)
		if payload["access_token"] == nil || payload["refresh_token"] == nil {
			t.Errorf("expected access_token and refresh_token in login response: %s", string(body))
		}
	})

	t.Run("AUTH-API-002: Wrong Password -> 401 Unauthorized", func(t *testing.T) {
		resp, _, _ := rig.doRequest("POST", "/api/v1/auth/login", "", map[string]string{
			"username": userEmail,
			"password": "WrongPassword123!",
		})
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("expected 401 on wrong password, got: %d", resp.StatusCode)
		}
	})

	t.Run("AUTH-API-003: Suspended User -> 401 Unauthorized (Anti-Enumeration)", func(t *testing.T) {
		_ = rig.mbSvc.Suspend(ctx, mb.ID)
		resp, _, _ := rig.doRequest("POST", "/api/v1/auth/login", "", map[string]string{
			"username": userEmail,
			"password": userPass,
		})
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("expected 401 for suspended user, got: %d", resp.StatusCode)
		}
		_ = rig.mbSvc.Resume(ctx, mb.ID)
	})


	t.Run("AUTH-API-007 & 008: Refresh Token Rotation and Replay Protection", func(t *testing.T) {
		// Login
		_, body, _ := rig.doRequest("POST", "/api/v1/auth/login", "", map[string]string{
			"username": userEmail,
			"password": userPass,
		})
		var loginResp map[string]interface{}
		_ = json.Unmarshal(body, &loginResp)
		rt := loginResp["refresh_token"].(string)

		// 1st Refresh -> PASS
		resp, refreshBody, err := rig.doRequest("POST", "/api/v1/auth/refresh", "", map[string]string{
			"refresh_token": rt,
		})
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("refresh failed: %d, body: %s", resp.StatusCode, string(refreshBody))
		}

		// 2nd Refresh with old token -> FAIL (Revoked on rotation)
		resp2, _, _ := rig.doRequest("POST", "/api/v1/auth/refresh", "", map[string]string{
			"refresh_token": rt,
		})
		if resp2.StatusCode != http.StatusUnauthorized {
			t.Errorf("expected 401 on replaying old refresh token, got: %d", resp2.StatusCode)
		}
	})

	t.Run("AUTH-API-009: Logout Revokes Tokens", func(t *testing.T) {
		resp, body, err := rig.doRequest("POST", "/api/v1/auth/login", "", map[string]string{
			"username": userEmail,
			"password": userPass,
		})
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("login failed: %d", resp.StatusCode)
		}
		var loginResp map[string]interface{}
		_ = json.Unmarshal(body, &loginResp)
		at := loginResp["access_token"].(string)
		rt := loginResp["refresh_token"].(string)

		// Logout
		respLogout, _, _ := rig.doRequest("POST", "/api/v1/auth/logout", at, map[string]string{
			"refresh_token": rt,
		})
		if respLogout.StatusCode != http.StatusOK {
			t.Errorf("logout failed: %d", respLogout.StatusCode)
		}

		// Using access token now -> 401 Unauthorized
		respMe, _, _ := rig.doRequest("GET", "/api/v1/auth/me", at, nil)
		if respMe.StatusCode != http.StatusUnauthorized {
			t.Errorf("expected 401 after logout, got: %d", respMe.StatusCode)
		}
	})
}

// 3. RBAC ENFORCEMENT MATRIX (RBAC-001 to RBAC-008)
func TestREST_API_RBAC(t *testing.T) {
	rig := setupAPITestRig(t)
	if rig == nil {
		return
	}
	defer rig.server.Close()
	defer rig.db.Close()

	ctx := context.Background()
	testDom := fmt.Sprintf("rbac-%d.com", time.Now().UnixNano())
	_, _ = rig.domSvc.Create(ctx, testDom)
	defer rig.domSvc.Delete(ctx, testDom)

	t.Run("RBAC-001: Admin has full access", func(t *testing.T) {
		resp, _, _ := rig.doRequest("GET", "/api/v1/domains", rig.adminToken, nil)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("admin domain list failed: %d", resp.StatusCode)
		}
	})

	t.Run("RBAC-002: Operator can list and create, but cannot delete queue messages", func(t *testing.T) {
		resp, _, _ := rig.doRequest("GET", "/api/v1/domains", rig.operToken, nil)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("operator domain list failed: %d", resp.StatusCode)
		}

		respDel, _, _ := rig.doRequest("DELETE", "/api/v1/queue/msg123", rig.operToken, nil)
		if respDel.StatusCode != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden for operator queue delete, got: %d", respDel.StatusCode)
		}
	})

	t.Run("RBAC-003: Auditor has read-only access (Mutations blocked with 403)", func(t *testing.T) {
		// Read -> OK
		resp, _, _ := rig.doRequest("GET", "/api/v1/domains", rig.auditToken, nil)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("auditor read failed: %d", resp.StatusCode)
		}

		// Write -> 403 Forbidden
		respWrite, _, _ := rig.doRequest("POST", "/api/v1/domains", rig.auditToken, map[string]string{"name": "hacked.com"})
		if respWrite.StatusCode != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden for auditor create domain, got: %d", respWrite.StatusCode)
		}
	})

	t.Run("RBAC-004: User cannot access administrative domain routes", func(t *testing.T) {
		resp, _, _ := rig.doRequest("GET", "/api/v1/domains", rig.userToken, nil)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden for regular user accessing domains, got: %d", resp.StatusCode)
		}
	})
}

// 4. DOMAIN & MAILBOX & ALIAS API (DOMAIN-001, MBX-001, ALIAS-001)
func TestREST_API_DomainAndMailbox(t *testing.T) {
	rig := setupAPITestRig(t)
	if rig == nil {
		return
	}
	defer rig.server.Close()
	defer rig.db.Close()

	domName := fmt.Sprintf("api-crud-%d.com", time.Now().UnixNano())

	t.Run("Domain CRUD, DKIM, Policy, Doctor, DNS", func(t *testing.T) {
		// 1. Create Domain
		resp, body, err := rig.doRequest("POST", "/api/v1/domains", rig.adminToken, map[string]string{"name": domName})
		if err != nil || resp.StatusCode != http.StatusCreated {
			t.Fatalf("create domain failed: %d, body: %s", resp.StatusCode, string(body))
		}

		// 2. Duplicate Domain -> 409 Conflict
		respDup, _, _ := rig.doRequest("POST", "/api/v1/domains", rig.adminToken, map[string]string{"name": domName})
		if respDup.StatusCode != http.StatusConflict {
			t.Errorf("expected 409 Conflict for duplicate domain, got: %d", respDup.StatusCode)
		}

		// 3. Get Domain
		respGet, getBody, _ := rig.doRequest("GET", "/api/v1/domains/"+domName, rig.adminToken, nil)
		if respGet.StatusCode != http.StatusOK || !strings.Contains(string(getBody), domName) {
			t.Errorf("get domain failed: %d, body: %s", respGet.StatusCode, string(getBody))
		}

		// 4. Policy Update
		respPol, _, _ := rig.doRequest("PUT", "/api/v1/domains/"+domName+"/policy", rig.adminToken, map[string]string{
			"spf_policy":   "v=spf1 mx -all",
			"dmarc_policy": "v=DMARC1; p=reject",
		})
		if respPol.StatusCode != http.StatusOK {
			t.Errorf("update policy failed: %d", respPol.StatusCode)
		}

		// 5. Doctor & DNS
		respDoc, _, _ := rig.doRequest("GET", "/api/v1/domains/"+domName+"/doctor", rig.adminToken, nil)
		if respDoc.StatusCode != http.StatusOK {
			t.Errorf("domain doctor failed: %d", respDoc.StatusCode)
		}

		respDNS, _, _ := rig.doRequest("GET", "/api/v1/domains/"+domName+"/dns", rig.adminToken, nil)
		if respDNS.StatusCode != http.StatusOK {
			t.Errorf("domain dns failed: %d", respDNS.StatusCode)
		}
	})

	userEmail := "user@" + domName
	t.Run("Mailbox CRUD, Quota, Lifecycle & Alias Management", func(t *testing.T) {
		// 1. Create Mailbox
		resp, body, err := rig.doRequest("POST", "/api/v1/mailboxes", rig.adminToken, map[string]interface{}{
			"email":       userEmail,
			"password":    "SecretPass123!",
			"quota_bytes": 1073741824,
		})
		if err != nil || resp.StatusCode != http.StatusCreated {
			t.Fatalf("create mailbox failed: %d, body: %s", resp.StatusCode, string(body))
		}

		// 2. Create Alias
		aliasEmail := "support@" + domName
		respAlias, aliasBody, err := rig.doRequest("POST", fmt.Sprintf("/api/v1/mailboxes/%s/aliases", userEmail), rig.adminToken, map[string]string{
			"source": aliasEmail,
		})
		if err != nil || respAlias.StatusCode != http.StatusCreated {
			t.Fatalf("create alias failed: %d, body: %s", respAlias.StatusCode, string(aliasBody))
		}

		// 3. List Aliases
		respList, listBody, _ := rig.doRequest("GET", fmt.Sprintf("/api/v1/mailboxes/%s/aliases", userEmail), rig.adminToken, nil)
		if respList.StatusCode != http.StatusOK || !strings.Contains(string(listBody), aliasEmail) {
			t.Errorf("list aliases failed: %s", string(listBody))
		}

		// 4. Quota Reconcile
		respQuota, _, _ := rig.doRequest("POST", fmt.Sprintf("/api/v1/mailboxes/%s/quota/reconcile", userEmail), rig.adminToken, nil)
		if respQuota.StatusCode != http.StatusOK {
			t.Errorf("quota reconcile failed: %d", respQuota.StatusCode)
		}

		// 5. Suspend and Resume Mailbox
		respSusp, _, _ := rig.doRequest("POST", fmt.Sprintf("/api/v1/mailboxes/%s/suspend", userEmail), rig.adminToken, nil)
		if respSusp.StatusCode != http.StatusOK {
			t.Errorf("suspend failed: %d", respSusp.StatusCode)
		}

		respRes, _, _ := rig.doRequest("POST", fmt.Sprintf("/api/v1/mailboxes/%s/resume", userEmail), rig.adminToken, nil)
		if respRes.StatusCode != http.StatusOK {
			t.Errorf("resume failed: %d", respRes.StatusCode)
		}
	})

	// Cleanup
	_, _, _ = rig.doRequest("DELETE", "/api/v1/domains/"+domName, rig.adminToken, nil)
}

// 5. LDAP & IDENTITY API (LDAP-API-001 to LDAP-API-010)
func TestREST_API_LDAPAndIdentity(t *testing.T) {
	rig := setupAPITestRig(t)
	if rig == nil {
		return
	}
	defer rig.server.Close()
	defer rig.db.Close()

	t.Run("LDAP-API-001: List Providers", func(t *testing.T) {
		resp, body, err := rig.doRequest("GET", "/api/v1/identity/providers", rig.adminToken, nil)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("list providers failed: %d, body: %s", resp.StatusCode, string(body))
		}
		if !strings.Contains(string(body), "ldap") || !strings.Contains(string(body), "local") {
			t.Errorf("expected providers ldap and local, got: %s", string(body))
		}
	})

	t.Run("LDAP-API-006: LDAP Sync Dry Run", func(t *testing.T) {
		resp, body, err := rig.doRequest("POST", "/api/v1/ldap/sync", rig.adminToken, map[string]interface{}{
			"domain_name": "example.com",
			"dry_run":     true,
		})
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("ldap sync dry run failed: %d, body: %s", resp.StatusCode, string(body))
		}
	})
}

// 6. GOLDEN E2E SCENARIO (GOLDEN-API-001)
func TestREST_API_GoldenE2E(t *testing.T) {
	rig := setupAPITestRig(t)
	if rig == nil {
		return
	}
	defer rig.server.Close()
	defer rig.db.Close()

	goldenDom := fmt.Sprintf("golden-api-%d.com", time.Now().UnixNano())

	// Step 1: Create Domain via API
	resp, body, err := rig.doRequest("POST", "/api/v1/domains", rig.adminToken, map[string]string{"name": goldenDom})
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("step 1 create domain failed: %d, body: %s", resp.StatusCode, string(body))
	}
	defer rig.doRequest("DELETE", "/api/v1/domains/"+goldenDom, rig.adminToken, nil)

	// Step 2: Generate DKIM Key via API
	respDKIM, _, err := rig.doRequest("POST", fmt.Sprintf("/api/v1/domains/%s/dkim", goldenDom), rig.adminToken, map[string]string{"selector": "default"})
	if err != nil || respDKIM.StatusCode != http.StatusCreated {
		t.Errorf("step 2 generate dkim failed: %d", respDKIM.StatusCode)
	}

	// Step 3: Create Mailbox via API
	userEmail := "ceo@" + goldenDom
	userPass := "CeoSecretPass123!"
	respMB, _, err := rig.doRequest("POST", "/api/v1/mailboxes", rig.adminToken, map[string]interface{}{
		"email":       userEmail,
		"password":    userPass,
		"quota_bytes": 2147483648,
	})
	if err != nil || respMB.StatusCode != http.StatusCreated {
		t.Fatalf("step 3 create mailbox failed: %d", respMB.StatusCode)
	}

	// Step 4: Login as newly created user via API -> Obtain user access token
	respLogin, loginBody, err := rig.doRequest("POST", "/api/v1/auth/login", "", map[string]string{
		"username": userEmail,
		"password": userPass,
	})
	if err != nil || respLogin.StatusCode != http.StatusOK {
		t.Fatalf("step 4 user login failed: %d, body: %s", respLogin.StatusCode, string(loginBody))
	}

	var loginPayload map[string]interface{}
	_ = json.Unmarshal(loginBody, &loginPayload)
	userJWT := loginPayload["access_token"].(string)

	// Step 5: User accesses self profile via API /api/v1/auth/me
	respMe, meBody, err := rig.doRequest("GET", "/api/v1/auth/me", userJWT, nil)
	if err != nil || respMe.StatusCode != http.StatusOK || !strings.Contains(string(meBody), userEmail) {
		t.Errorf("step 5 get me failed: %d, body: %s", respMe.StatusCode, string(meBody))
	}

	// Step 6: Query System Doctor
	respDoc, _, err := rig.doRequest("GET", "/api/v1/system/doctor", rig.adminToken, nil)
	if err != nil || respDoc.StatusCode != http.StatusOK {
		t.Errorf("step 6 system doctor failed: %d", respDoc.StatusCode)
	}
}

// 7. CONCURRENCY (CONC-API-001)
func TestREST_API_Concurrency(t *testing.T) {
	rig := setupAPITestRig(t)
	if rig == nil {
		return
	}
	defer rig.server.Close()
	defer rig.db.Close()

	const workers = 30
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			resp, _, err := rig.doRequest("GET", "/health/live", "", nil)
			if err != nil || resp.StatusCode != http.StatusOK {
				t.Errorf("worker %d failed: %v", id, err)
			}
		}(i)
	}
	wg.Wait()
}
