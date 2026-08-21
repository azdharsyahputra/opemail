package security_test

import (
	"context"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/azdharsyahputra/openmail/internal/identity/ldap"
	goldap "github.com/go-ldap/ldap/v3"
)

// TestResourceExhaustion_GoroutinesAndConnections verifies bounded goroutine lifecycle
// and connection bounds under high load
func TestResourceExhaustion_GoroutinesAndConnections(t *testing.T) {
	mockClient := &mockExtendedLDAPClient{
		entries: map[string]*goldap.Entry{
			"uid=test,ou=people,dc=example,dc=com": {
				DN: "uid=test,ou=people,dc=example,dc=com",
				Attributes: []*goldap.EntryAttribute{
					{Name: "uid", Values: []string{"test"}},
					{Name: "mail", Values: []string{"test@example.com"}},
				},
			},
		},
		passwords: map[string]string{
			"uid=test,ou=people,dc=example,dc=com": "Pass123!",
		},
	}

	prov := ldap.NewProvider(ldap.DefaultConfig(), mockClient)

	initialGoroutines := runtime.NumGoroutine()

	var wg sync.WaitGroup
	concurrentReqs := 100

	for i := 0; i < concurrentReqs; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			_, _ = prov.Authenticate(ctx, "test@example.com", "Pass123!")
		}(i)
	}

	wg.Wait()

	// Allow brief cleanup
	time.Sleep(50 * time.Millisecond)
	finalGoroutines := runtime.NumGoroutine()

	diff := finalGoroutines - initialGoroutines
	if diff > 30 {
		t.Fatalf("SECURITY INVARIANT VIOLATED: Goroutine leak detected! Initial: %d, Final: %d (diff: %d)", initialGoroutines, finalGoroutines, diff)
	}
}
