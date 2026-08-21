package ldap_test

import (
	"testing"

	"github.com/azdharsyahputra/openmail/internal/identity"
	"github.com/azdharsyahputra/openmail/internal/identity/ldap"
	goldap "github.com/go-ldap/ldap/v3"
)

func TestLDAP_Mapper(t *testing.T) {
	mapper := ldap.NewMapper(map[string]string{
		"mail-admins":    "admin",
		"mail-operators": "operator",
	})

	entry := &goldap.Entry{
		DN: "uid=ajar,ou=people,dc=example,dc=com",
		Attributes: []*goldap.EntryAttribute{
			{Name: "uid", Values: []string{"ajar"}},
			{Name: "mail", Values: []string{"ajar@example.com"}},
			{Name: "cn", Values: []string{"Ajar Dev"}},
			{Name: "givenName", Values: []string{"Ajar"}},
			{Name: "sn", Values: []string{"Dev"}},
			{Name: "memberOf", Values: []string{
				"cn=mail-admins,ou=groups,dc=example,dc=com",
				"cn=engineering,ou=groups,dc=example,dc=com",
			}},
		},
	}

	id := mapper.EntryToIdentity(entry)
	if id == nil {
		t.Fatalf("expected non-nil identity")
	}

	if id.Username != "ajar" {
		t.Errorf("expected username ajar, got %s", id.Username)
	}
	if id.Email != "ajar@example.com" {
		t.Errorf("expected email ajar@example.com, got %s", id.Email)
	}
	if id.DisplayName != "Ajar Dev" {
		t.Errorf("expected display name 'Ajar Dev', got %s", id.DisplayName)
	}
	if id.Status != identity.StatusActive {
		t.Errorf("expected active status, got %s", id.Status)
	}

	// Verify RBAC mapped role
	hasAdmin := false
	for _, r := range id.Roles {
		if r == identity.RoleAdmin {
			hasAdmin = true
		}
	}
	if !hasAdmin {
		t.Errorf("expected RoleAdmin mapped from group mail-admins, roles: %+v", id.Roles)
	}
}

func TestLDAP_MapperDisabledAccount(t *testing.T) {
	mapper := ldap.NewMapper(nil)

	entry := &goldap.Entry{
		DN: "uid=disableduser,ou=people,dc=example,dc=com",
		Attributes: []*goldap.EntryAttribute{
			{Name: "uid", Values: []string{"disableduser"}},
			{Name: "mail", Values: []string{"disabled@example.com"}},
			{Name: "accountStatus", Values: []string{"disabled"}},
		},
	}

	id := mapper.EntryToIdentity(entry)
	if id.Status != identity.StatusDisabled {
		t.Errorf("expected status disabled, got %s", id.Status)
	}
}
