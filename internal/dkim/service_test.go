package dkim_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"


	"github.com/azdharsyahputra/openmail/internal/dkim"
	"github.com/azdharsyahputra/openmail/internal/domain"
	"github.com/google/uuid"
)

type mockDKIMRepo struct {
	keys     map[string]*dkim.DKIMKey
	policies map[uuid.UUID]*dkim.DomainMailPolicy
}

func newMockDKIMRepo() *mockDKIMRepo {
	return &mockDKIMRepo{
		keys:     make(map[string]*dkim.DKIMKey),
		policies: make(map[uuid.UUID]*dkim.DomainMailPolicy),
	}
}

func (m *mockDKIMRepo) CreateDKIMKey(ctx context.Context, key *dkim.DKIMKey) error {
	lookupKey := key.DomainID.String() + ":" + key.Selector
	if _, ok := m.keys[lookupKey]; ok {
		return dkim.ErrDKIMKeyExists
	}
	m.keys[lookupKey] = key
	return nil
}

func (m *mockDKIMRepo) GetDKIMKeyByID(ctx context.Context, id uuid.UUID) (*dkim.DKIMKey, error) {
	for _, k := range m.keys {
		if k.ID == id {
			return k, nil
		}
	}
	return nil, dkim.ErrDKIMKeyNotFound
}

func (m *mockDKIMRepo) GetDKIMKeyBySelector(ctx context.Context, domainID uuid.UUID, selector string) (*dkim.DKIMKey, error) {
	lookupKey := domainID.String() + ":" + selector
	k, ok := m.keys[lookupKey]
	if !ok {
		return nil, dkim.ErrDKIMKeyNotFound
	}
	return k, nil
}

func (m *mockDKIMRepo) GetActiveDKIMKey(ctx context.Context, domainID uuid.UUID) (*dkim.DKIMKey, error) {
	for _, k := range m.keys {
		if k.DomainID == domainID && k.Status == dkim.StatusActive {
			return k, nil
		}
	}
	return nil, dkim.ErrDKIMKeyNotFound
}

func (m *mockDKIMRepo) ListDKIMKeysByDomain(ctx context.Context, domainID uuid.UUID) ([]*dkim.DKIMKey, error) {
	var list []*dkim.DKIMKey
	for _, k := range m.keys {
		if k.DomainID == domainID {
			list = append(list, k)
		}
	}
	return list, nil
}

func (m *mockDKIMRepo) ActivateDKIMKey(ctx context.Context, id uuid.UUID) error {
	k, err := m.GetDKIMKeyByID(ctx, id)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	k.Status = dkim.StatusActive
	k.ActivatedAt = &now
	return nil
}

func (m *mockDKIMRepo) RevokeDKIMKey(ctx context.Context, id uuid.UUID) error {
	k, err := m.GetDKIMKeyByID(ctx, id)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	k.Status = dkim.StatusRevoked
	k.RevokedAt = &now
	return nil
}

func (m *mockDKIMRepo) GetPolicy(ctx context.Context, domainID uuid.UUID) (*dkim.DomainMailPolicy, error) {
	p, ok := m.policies[domainID]
	if !ok {
		return nil, dkim.ErrPolicyNotFound
	}
	return p, nil
}

func (m *mockDKIMRepo) UpsertPolicy(ctx context.Context, policy *dkim.DomainMailPolicy) error {
	m.policies[policy.DomainID] = policy
	return nil
}

type mockDomainRepo struct {
	domains map[string]*domain.Domain
}

func newMockDomainRepo() *mockDomainRepo {
	return &mockDomainRepo{domains: make(map[string]*domain.Domain)}
}

func (m *mockDomainRepo) Create(ctx context.Context, d *domain.Domain) error {
	m.domains[d.Name] = d
	return nil
}
func (m *mockDomainRepo) GetByID(ctx context.Context, id uuid.UUID) (*domain.Domain, error) {
	for _, d := range m.domains {
		if d.ID == id {
			return d, nil
		}
	}
	return nil, domain.ErrDomainNotFound
}
func (m *mockDomainRepo) GetByName(ctx context.Context, name string) (*domain.Domain, error) {
	d, ok := m.domains[name]
	if !ok {
		return nil, domain.ErrDomainNotFound
	}
	return d, nil
}
func (m *mockDomainRepo) List(ctx context.Context) ([]*domain.Domain, error) {
	var list []*domain.Domain
	for _, d := range m.domains {
		list = append(list, d)
	}
	return list, nil
}
func (m *mockDomainRepo) Delete(ctx context.Context, name string) error {
	if _, ok := m.domains[name]; ok {
		delete(m.domains, name)
		return nil
	}
	return domain.ErrDomainNotFound
}


func TestDKIMSelectorValidation(t *testing.T) {
	validSelectors := []string{
		"mailopen2026",
		"s1",
		"k1-2026",
		"dkim_2026.rsa",
	}

	for _, sel := range validSelectors {
		if err := dkim.ValidateSelector(sel); err != nil {
			t.Errorf("expected selector %s to be valid, got: %v", sel, err)
		}
	}

	invalidSelectors := []string{
		"",
		"../mailopen2026",
		"mail/open",
		"mail\\open",
		"mail open",
		"mail@open",
		"-invalidstart",
		"_invalidstart",
	}

	for _, sel := range invalidSelectors {
		if err := dkim.ValidateSelector(sel); err == nil {
			t.Errorf("expected selector %s to be invalid, but passed", sel)
		}
	}
}

func TestDKIMKeygenAndKeystore(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "openmail-dkim-test-*")
	if err != nil {
		t.Fatalf("temp dir error: %v", err)
	}
	defer os.RemoveAll(tempDir)

	keystore := dkim.NewFilesystemKeystore(tempDir)

	t.Run("RSA-2048 Key Generation and Validation", func(t *testing.T) {
		pair, err := dkim.GenerateRSAKeyPair(2048)
		if err != nil {
			t.Fatalf("failed to generate RSA-2048 key: %v", err)
		}

		privKey, err := dkim.ValidatePrivateKey(pair.PrivateKeyPEM)
		if err != nil {
			t.Fatalf("failed to validate generated private key: %v", err)
		}
		if privKey.N.BitLen() != 2048 {
			t.Errorf("expected 2048 bit RSA key, got %d", privKey.N.BitLen())
		}

		// Store in Keystore
		path, err := keystore.StorePrivateKey(context.Background(), "example.com", "mailopen2026", pair.PrivateKeyPEM)
		if err != nil {
			t.Fatalf("failed to store private key: %v", err)
		}

		// Check permissions
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("key file not found: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0600 {
			t.Errorf("expected key file permission 0600, got %04o", perm)
		}

		dirInfo, err := os.Stat(filepath.Dir(path))
		if err != nil {
			t.Fatalf("key directory not found: %v", err)
		}
		if dirPerm := dirInfo.Mode().Perm(); dirPerm != 0750 {
			t.Errorf("expected key dir permission 0750, got %04o", dirPerm)
		}
	})

	t.Run("Public / Private Key Match & Mismatch", func(t *testing.T) {
		pair1, _ := dkim.GenerateRSAKeyPair(2048)
		pair2, _ := dkim.GenerateRSAKeyPair(2048)

		priv1, _ := dkim.ParseRSAPrivateKey(pair1.PrivateKeyPEM)
		pub1, _ := dkim.ParseRSAPublicKeyFromDNS(pair1.PublicKeyDNS)
		pub2, _ := dkim.ParseRSAPublicKeyFromDNS(pair2.PublicKeyDNS)

		if !dkim.ValidatePublicKeyMatch(priv1, pub1) {
			t.Error("expected matching keypair to return true")
		}

		if dkim.ValidatePublicKeyMatch(priv1, pub2) {
			t.Error("expected mismatched keypair to return false")
		}
	})
}

func TestDKIMServiceLifecycleAndRotation(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "openmail-dkim-lifecycle-*")
	if err != nil {
		t.Fatalf("temp dir error: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dkimRepo := newMockDKIMRepo()
	domainRepo := newMockDomainRepo()
	keystore := dkim.NewFilesystemKeystore(tempDir)
	svc := dkim.NewService(dkimRepo, domainRepo, keystore)

	domID := uuid.New()
	_ = domainRepo.Create(context.Background(), &domain.Domain{
		ID:     domID,
		Name:   "example.com",
		Status: "active",
	})


	ctx := context.Background()

	// 1. Generate key for selector mailopen2026
	key1, pair1, err := svc.GenerateKey(ctx, "example.com", "mailopen2026")
	if err != nil {
		t.Fatalf("generate key failed: %v", err)
	}
	if key1.Status != dkim.StatusPending {
		t.Errorf("expected initial status to be pending, got %s", key1.Status)
	}

	// 2. Mock DNS Verification
	mockDNSLookup := func(name string) ([]string, error) {
		if name == "mailopen2026._domainkey.example.com" {
			return []string{"v=DKIM1; k=rsa; p=" + pair1.PublicKeyDNS}, nil
		}
		return nil, nil
	}

	verRes, err := svc.VerifyDNS(ctx, "example.com", "mailopen2026", mockDNSLookup)
	if err != nil {
		t.Fatalf("VerifyDNS failed: %v", err)
	}
	if verRes.Status != "VERIFIED" || !verRes.KeyMatches {
		t.Errorf("expected VERIFIED status, got %s (message: %s)", verRes.Status, verRes.Message)
	}

	// 3. Activate selector
	if err := svc.ActivateKey(ctx, "example.com", "mailopen2026"); err != nil {
		t.Fatalf("activate key failed: %v", err)
	}

	activeKey, err := svc.GetActiveKey(ctx, "example.com")
	if err != nil || activeKey.Selector != "mailopen2026" {
		t.Errorf("expected active key mailopen2026, got %v", activeKey)
	}

	// 4. Rotation: Generate new selector mailopen2027
	key2, pair2, err := svc.GenerateKey(ctx, "example.com", "mailopen2027")
	if err != nil {
		t.Fatalf("generate rotated key failed: %v", err)
	}
	_ = key2


	mockDNSLookupRotated := func(name string) ([]string, error) {
		if name == "mailopen2026._domainkey.example.com" {
			return []string{"v=DKIM1; k=rsa; p=" + pair1.PublicKeyDNS}, nil
		}
		if name == "mailopen2027._domainkey.example.com" {
			return []string{"v=DKIM1; k=rsa; p=" + pair2.PublicKeyDNS}, nil
		}
		return nil, nil
	}

	verRes2, err := svc.VerifyDNS(ctx, "example.com", "mailopen2027", mockDNSLookupRotated)
	if err != nil || verRes2.Status != "VERIFIED" {
		t.Fatalf("VerifyDNS for rotated key failed: %v", err)
	}

	// Activate new selector mailopen2027
	if err := svc.ActivateKey(ctx, "example.com", "mailopen2027"); err != nil {
		t.Fatalf("activate rotated key failed: %v", err)
	}

	// 5. Old key remains accessible during transition
	oldKey, err := dkimRepo.GetDKIMKeyBySelector(ctx, domID, "mailopen2026")
	if err != nil {
		t.Fatalf("expected old key to still exist: %v", err)
	}
	_ = oldKey

	// 6. Revoke old selector mailopen2026
	if err := svc.RevokeKey(ctx, "example.com", "mailopen2026"); err != nil {
		t.Fatalf("revoke old key failed: %v", err)
	}

	revokedKey, _ := dkimRepo.GetDKIMKeyBySelector(ctx, domID, "mailopen2026")
	if revokedKey.Status != dkim.StatusRevoked {
		t.Errorf("expected revoked status, got %s", revokedKey.Status)
	}
}

func TestOpenDKIMConfigGeneration(t *testing.T) {
	opts := dkim.OpenDKIMConfigOptions{
		ConfigDir:   "/etc/mailopen/opendkim",
		DKIMBaseDir: "/etc/mailopen/dkim",
		SocketPath:  "/var/spool/postfix/private/opendkim",
		ActiveKeys: []*dkim.DKIMKey{
			{
				Domain:   "example.com",
				Selector: "mailopen2026",
				Status:   dkim.StatusActive,
			},
		},
	}

	configs := dkim.GenerateOpenDKIMConfigs(opts)

	if !stringsContains(configs.OpenDKIMConf, "Socket                  local:/var/spool/postfix/private/opendkim") {
		t.Errorf("opendkim.conf missing socket directive")
	}

	if !stringsContains(configs.KeyTable, "mailopen2026._domainkey.example.com example.com:mailopen2026:/etc/mailopen/dkim/example.com/mailopen2026/private.key") {
		t.Errorf("KeyTable missing expected mapping, got:\n%s", configs.KeyTable)
	}

	if !stringsContains(configs.SigningTable, "*@example.com mailopen2026._domainkey.example.com") {
		t.Errorf("SigningTable missing wildcard mapping, got:\n%s", configs.SigningTable)
	}
}

func stringsContains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || (len(s) > 0 && len(substr) > 0 && searchSubstr(s, substr)))
}

func searchSubstr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
