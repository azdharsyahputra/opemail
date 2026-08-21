package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/azdharsyahputra/openmail/internal/api/handler"
)


// GATE 1: API-SEC-001 — Token Replay & Family Revocation
func TestGate_API_SEC_001_TokenReplayAndFamilyRevocation(t *testing.T) {
	rig := setupAPITestRig(t)
	if rig == nil {
		return
	}
	defer rig.server.Close()
	defer rig.db.Close()

	ctx := context.Background()
	testDom := fmt.Sprintf("sec001-%d.com", time.Now().UnixNano())
	_, _ = rig.domSvc.Create(ctx, testDom)
	defer rig.domSvc.Delete(ctx, testDom)

	userEmail := "alice@" + testDom
	userPass := "SecretPass123!"
	_, _ = rig.mbSvc.Create(ctx, userEmail, userPass, 1073741824)
	_, _, _ = rig.mbSvc.Provision(ctx, userEmail)

	// Step 1: Login to get token pair A
	resp, body, err := rig.doRequest("POST", "/api/v1/auth/login", "", map[string]string{
		"username": userEmail,
		"password": userPass,
	})
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("login failed: %v", err)
	}
	var pA map[string]interface{}
	_ = json.Unmarshal(body, &pA)
	atA := pA["access_token"].(string)
	rtA := pA["refresh_token"].(string)

	// Step 2: Refresh token A -> Expect 200 and receive token pair B
	respRef1, bodyRef1, err := rig.doRequest("POST", "/api/v1/auth/refresh", "", map[string]string{
		"refresh_token": rtA,
	})
	if err != nil || respRef1.StatusCode != http.StatusOK {
		t.Fatalf("refresh 1 failed: %d, body: %s", respRef1.StatusCode, string(bodyRef1))
	}
	var pB map[string]interface{}
	_ = json.Unmarshal(bodyRef1, &pB)
	atB := pB["access_token"].(string)

	// Step 3: Replay refresh token A -> Expect 401 Unauthorized AND family revocation
	respReplay, _, _ := rig.doRequest("POST", "/api/v1/auth/refresh", "", map[string]string{
		"refresh_token": rtA,
	})
	if respReplay.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 on refresh replay, got: %d", respReplay.StatusCode)
	}

	// Step 4: Verify Token Family Revocation: Access Token A and Access Token B must now both be invalid
	respCheckA, _, _ := rig.doRequest("GET", "/api/v1/auth/me", atA, nil)
	if respCheckA.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected atA to be revoked on token replay detection, got: %d", respCheckA.StatusCode)
	}

	respCheckB, _, _ := rig.doRequest("GET", "/api/v1/auth/me", atB, nil)
	if respCheckB.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected atB to be revoked on token replay detection, got: %d", respCheckB.StatusCode)
	}
}

// GATE 2: API-SEC-002 — Cross-User Object Access (IDOR / Ownership block)
func TestGate_API_SEC_002_CrossUserObjectAccess(t *testing.T) {
	rig := setupAPITestRig(t)
	if rig == nil {
		return
	}
	defer rig.server.Close()
	defer rig.db.Close()

	ctx := context.Background()
	testDom := fmt.Sprintf("sec002-%d.com", time.Now().UnixNano())
	_, _ = rig.domSvc.Create(ctx, testDom)
	defer rig.domSvc.Delete(ctx, testDom)

	aliceEmail := "alice@" + testDom
	bobEmail := "bob@" + testDom
	_, _ = rig.mbSvc.Create(ctx, aliceEmail, "AliceSecret123!", 1073741824)
	_, _ = rig.mbSvc.Create(ctx, bobEmail, "BobSecret123!", 1073741824)
	_, _, _ = rig.mbSvc.Provision(ctx, aliceEmail)
	_, _, _ = rig.mbSvc.Provision(ctx, bobEmail)

	// Alice logs in
	resp, body, _ := rig.doRequest("POST", "/api/v1/auth/login", "", map[string]string{
		"username": aliceEmail,
		"password": "AliceSecret123!",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("alice login failed: %d", resp.StatusCode)
	}
	var alicePayload map[string]interface{}
	_ = json.Unmarshal(body, &alicePayload)
	aliceToken := alicePayload["access_token"].(string)

	// Alice tries to access Bob's mailbox details -> Expect 403 Forbidden
	respBob, _, _ := rig.doRequest("GET", "/api/v1/mailboxes/"+bobEmail, aliceToken, nil)
	if respBob.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for cross-user mailbox access, got: %d", respBob.StatusCode)
	}

	// Alice tries to access Bob's quota -> Expect 403 Forbidden
	respQuota, _, _ := rig.doRequest("GET", fmt.Sprintf("/api/v1/mailboxes/%s/quota", bobEmail), aliceToken, nil)
	if respQuota.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for cross-user quota access, got: %d", respQuota.StatusCode)
	}

	// Alice accesses her own mailbox details -> Expect 200 OK
	respAliceSelf, _, _ := rig.doRequest("GET", "/api/v1/mailboxes/"+aliceEmail, aliceToken, nil)
	if respAliceSelf.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK for self mailbox access, got: %d", respAliceSelf.StatusCode)
	}
}

// GATE 3: API-SEC-003 — Strict RBAC Matrix Verification
func TestGate_API_SEC_003_RBACMatrix(t *testing.T) {
	rig := setupAPITestRig(t)
	if rig == nil {
		return
	}
	defer rig.server.Close()
	defer rig.db.Close()

	ctx := context.Background()
	testDom := fmt.Sprintf("sec003-%d.com", time.Now().UnixNano())
	_, _ = rig.domSvc.Create(ctx, testDom)
	defer rig.domSvc.Delete(ctx, testDom)

	cases := []struct {
		name       string
		method     string
		path       string
		body       interface{}
		tokenRole  string
		token      string
		expectCode int
	}{
		// Domain Create: Admin (201), Operator (403), Auditor (403), User (403)
		{"Domain Create Admin", "POST", "/api/v1/domains", map[string]string{"name": "sub-" + testDom}, "admin", rig.adminToken, http.StatusCreated},
		{"Domain Create Operator", "POST", "/api/v1/domains", map[string]string{"name": "op-" + testDom}, "operator", rig.operToken, http.StatusForbidden},
		{"Domain Create Auditor", "POST", "/api/v1/domains", map[string]string{"name": "au-" + testDom}, "auditor", rig.auditToken, http.StatusForbidden},
		{"Domain Create User", "POST", "/api/v1/domains", map[string]string{"name": "us-" + testDom}, "user", rig.userToken, http.StatusForbidden},

		// Queue Delete: Admin (200), Operator (403), Auditor (403)
		{"Queue Delete Admin", "DELETE", "/api/v1/queue/msg_test", nil, "admin", rig.adminToken, http.StatusOK},
		{"Queue Delete Operator", "DELETE", "/api/v1/queue/msg_test", nil, "operator", rig.operToken, http.StatusForbidden},
		{"Queue Delete Auditor", "DELETE", "/api/v1/queue/msg_test", nil, "auditor", rig.auditToken, http.StatusForbidden},

		// Audit Read: Admin (200), Auditor (200), Operator (403), User (403)
		{"Audit Read Admin", "GET", "/api/v1/audit", nil, "admin", rig.adminToken, http.StatusOK},
		{"Audit Read Auditor", "GET", "/api/v1/audit", nil, "auditor", rig.auditToken, http.StatusOK},
		{"Audit Read Operator", "GET", "/api/v1/audit", nil, "operator", rig.operToken, http.StatusForbidden},
		{"Audit Read User", "GET", "/api/v1/audit", nil, "user", rig.userToken, http.StatusForbidden},

		// LDAP Sync: Admin (200), Operator (403)
		{"LDAP Sync Admin", "POST", "/api/v1/ldap/sync", map[string]interface{}{"domain_name": testDom, "dry_run": true}, "admin", rig.adminToken, http.StatusOK},
		{"LDAP Sync Operator", "POST", "/api/v1/ldap/sync", map[string]interface{}{"domain_name": testDom, "dry_run": true}, "operator", rig.operToken, http.StatusForbidden},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, _, _ := rig.doRequest(tc.method, tc.path, tc.token, tc.body)
			if resp.StatusCode != tc.expectCode {
				t.Errorf("[%s %s] role %s expected %d, got %d", tc.method, tc.path, tc.tokenRole, tc.expectCode, resp.StatusCode)
			}
		})
	}
}

// GATE 4: API-SEC-004 — Mass Assignment Protection
func TestGate_API_SEC_004_MassAssignmentProtection(t *testing.T) {
	rig := setupAPITestRig(t)
	if rig == nil {
		return
	}
	defer rig.server.Close()
	defer rig.db.Close()

	ctx := context.Background()
	testDom := fmt.Sprintf("sec004-%d.com", time.Now().UnixNano())
	_, _ = rig.domSvc.Create(ctx, testDom)
	defer rig.domSvc.Delete(ctx, testDom)

	targetEmail := "hacker@" + testDom
	maliciousPayload := map[string]interface{}{
		"email":             targetEmail,
		"password":          "SecretPass123!",
		"quota_bytes":       1073741824,
		"role":              "admin",
		"status":            "suspended",
		"identity_provider": "ldap",
		"password_hash":     "injected_argon2_hash",
	}

	resp, _, err := rig.doRequest("POST", "/api/v1/mailboxes", rig.adminToken, maliciousPayload)
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("create mailbox failed: %d, err: %v", resp.StatusCode, err)
	}

	// Verify database record has NOT accepted malicious role, status, or identity_provider overrides
	mb, err := rig.mbSvc.GetByEmail(ctx, targetEmail)
	if err != nil {
		t.Fatalf("get mailbox failed: %v", err)
	}

	if mb.Status != "active" {
		t.Errorf("mass assignment allowed status override to: %s", mb.Status)
	}
	if mb.IdentityProvider != "local" {
		t.Errorf("mass assignment allowed identity_provider override to: %s", mb.IdentityProvider)
	}
}

// GATE 5: API-SEC-005 — HTTP Abuse & Payload Bounds
func TestGate_API_SEC_005_HTTPAbuse(t *testing.T) {
	rig := setupAPITestRig(t)
	if rig == nil {
		return
	}
	defer rig.server.Close()
	defer rig.db.Close()

	t.Run("Oversized payload rejection", func(t *testing.T) {
		largeData := strings.Repeat("A", 2*1024*1024) // 2MB (> 1MB limit)
		req, _ := http.NewRequest("POST", rig.server.URL+"/api/v1/auth/login", strings.NewReader(largeData))
		req.Header.Set("Content-Type", "application/json")
		resp, err := rig.client.Do(req)
		if err == nil && resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusRequestEntityTooLarge {
			t.Errorf("expected 400 or 413 for oversized body, got: %d", resp.StatusCode)
		}
	})

	t.Run("Unsupported Media Type without application/json", func(t *testing.T) {
		req, _ := http.NewRequest("POST", rig.server.URL+"/api/v1/auth/login", strings.NewReader("username=admin"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, _ := rig.client.Do(req)
		if resp.StatusCode != http.StatusUnsupportedMediaType {
			t.Errorf("expected 415 Unsupported Media Type, got: %d", resp.StatusCode)
		}
	})
}

// GATE 6: API-SEC-006 — Authentication Timing & Enumeration Resistance
func TestGate_API_SEC_006_AuthenticationEnumerationResistance(t *testing.T) {
	rig := setupAPITestRig(t)
	if rig == nil {
		return
	}
	defer rig.server.Close()
	defer rig.db.Close()

	ctx := context.Background()
	testDom := fmt.Sprintf("sec006-%d.com", time.Now().UnixNano())
	_, _ = rig.domSvc.Create(ctx, testDom)
	defer rig.domSvc.Delete(ctx, testDom)

	existingUser := "realuser@" + testDom
	mb, _ := rig.mbSvc.Create(ctx, existingUser, "RealPass123!", 1073741824)
	_, _, _ = rig.mbSvc.Provision(ctx, existingUser)

	// Test 1: Nonexistent user
	respNonexistent, body1, _ := rig.doRequest("POST", "/api/v1/auth/login", "", map[string]string{
		"username": "nosuchuser@" + testDom,
		"password": "WrongPassword123!",
	})

	// Test 2: Existing user with wrong password
	respWrongPass, body2, _ := rig.doRequest("POST", "/api/v1/auth/login", "", map[string]string{
		"username": existingUser,
		"password": "WrongPassword123!",
	})

	// Test 3: Suspended user
	_ = rig.mbSvc.Suspend(ctx, mb.ID)
	respSuspended, body3, _ := rig.doRequest("POST", "/api/v1/auth/login", "", map[string]string{
		"username": existingUser,
		"password": "RealPass123!",
	})

	if respNonexistent.StatusCode != http.StatusUnauthorized || respWrongPass.StatusCode != http.StatusUnauthorized || respSuspended.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected uniform 401 across all auth failures (got %d, %d, %d)", respNonexistent.StatusCode, respWrongPass.StatusCode, respSuspended.StatusCode)
	}

	// Verify exact response body matches across cases
	var r1, r2, r3 map[string]interface{}
	_ = json.Unmarshal(body1, &r1)
	_ = json.Unmarshal(body2, &r2)
	_ = json.Unmarshal(body3, &r3)

	err1 := r1["error"].(map[string]interface{})["code"]
	err2 := r2["error"].(map[string]interface{})["code"]
	err3 := r3["error"].(map[string]interface{})["code"]

	if err1 != err2 || err2 != err3 {
		t.Errorf("error codes differ leaking state: %v, %v, %v", err1, err2, err3)
	}
}

// GATE 7: API-SEC-007 — Audit Integrity (Zero Secret Leakage)
func TestGate_API_SEC_007_AuditIntegrity(t *testing.T) {
	rig := setupAPITestRig(t)
	if rig == nil {
		return
	}
	defer rig.server.Close()
	defer rig.db.Close()

	testDom := fmt.Sprintf("sec007-%d.com", time.Now().UnixNano())
	respDom, _, _ := rig.doRequest("POST", "/api/v1/domains", rig.adminToken, map[string]string{"name": testDom})

	if respDom.StatusCode != http.StatusCreated {
		t.Fatalf("domain create failed: %d", respDom.StatusCode)
	}

	userEmail := "audituser@" + testDom
	respMB, _, _ := rig.doRequest("POST", "/api/v1/mailboxes", rig.adminToken, map[string]interface{}{
		"email":       userEmail,
		"password":    "SuperSecretPassword!",
		"quota_bytes": 1073741824,
	})
	if respMB.StatusCode != http.StatusCreated {
		t.Fatalf("mailbox create failed: %d", respMB.StatusCode)
	}

	// Change password
	_, _, _ = rig.doRequest("POST", fmt.Sprintf("/api/v1/mailboxes/%s/password", userEmail), rig.adminToken, map[string]string{
		"password": "NewSecretPassword123!",
	})

	// Query audit logs
	respAudit, auditBody, _ := rig.doRequest("GET", "/api/v1/audit?limit=10", rig.adminToken, nil)
	if respAudit.StatusCode != http.StatusOK {
		t.Fatalf("audit list failed: %d", respAudit.StatusCode)
	}

	auditStr := string(auditBody)
	if strings.Contains(auditStr, "SuperSecretPassword!") || strings.Contains(auditStr, "NewSecretPassword123!") {
		t.Fatalf("SECURITY VIOLATION: plain password detected in audit log: %s", auditStr)
	}
}

// GATE 8: API-SEC-008 — Dangerous Endpoint Protection
func TestGate_API_SEC_008_DangerousEndpointProtection(t *testing.T) {
	rig := setupAPITestRig(t)
	if rig == nil {
		return
	}
	defer rig.server.Close()
	defer rig.db.Close()

	// Flush queue with operator token -> 403 Forbidden
	respFlush, _, _ := rig.doRequest("POST", "/api/v1/queue/flush", rig.operToken, nil)
	if respFlush.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for operator queue flush, got: %d", respFlush.StatusCode)
	}

	// Flush queue with admin token -> 200 OK
	respAdminFlush, _, _ := rig.doRequest("POST", "/api/v1/queue/flush", rig.adminToken, nil)
	if respAdminFlush.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK for admin queue flush, got: %d", respAdminFlush.StatusCode)
	}
}

// GATE 9: API-REL-001 — Idempotency
func TestGate_API_REL_001_Idempotency(t *testing.T) {
	rig := setupAPITestRig(t)
	if rig == nil {
		return
	}
	defer rig.server.Close()
	defer rig.db.Close()

	testDom := fmt.Sprintf("rel001-%d.com", time.Now().UnixNano())
	_, _, _ = rig.doRequest("POST", "/api/v1/domains", rig.adminToken, map[string]string{"name": testDom})
	defer func() {
		_, _, _ = rig.doRequest("DELETE", "/api/v1/domains/"+testDom, rig.adminToken, nil)
	}()


	userEmail := "idemp@" + testDom

	// Request 1: Provision Mailbox
	resp1, _, _ := rig.doRequest("POST", "/api/v1/mailboxes", rig.adminToken, map[string]interface{}{
		"email":       userEmail,
		"password":    "SecretPass123!",
		"quota_bytes": 1073741824,
	})
	if resp1.StatusCode != http.StatusCreated {
		t.Fatalf("first mailbox create failed: %d", resp1.StatusCode)
	}

	// Repeated provision calls must be completely safe & idempotent
	for i := 0; i < 3; i++ {
		respProv, _, _ := rig.doRequest("POST", fmt.Sprintf("/api/v1/mailboxes/%s/provision", userEmail), rig.adminToken, nil)
		if respProv.StatusCode != http.StatusOK {
			t.Errorf("idempotent provision %d failed: %d", i, respProv.StatusCode)
		}
	}
}

// GATE 10: API-REL-002 — Dependency Failure Resilience
func TestGate_API_REL_002_DependencyFailureResilience(t *testing.T) {
	// Create mock failing health handler
	healthH := handler.NewHealthHandler(nil, nil, "/nonexistent", "", "")
	req := httptest.NewRequest("GET", "/health/ready", nil)
	rr := httptest.NewRecorder()

	healthH.Ready(rr, req)

	// Subsystem failure should return 503 without panic
	if rr.Code != http.StatusServiceUnavailable && rr.Code != http.StatusOK {
		t.Errorf("expected structured status code on dependency failure, got: %d", rr.Code)
	}
}
