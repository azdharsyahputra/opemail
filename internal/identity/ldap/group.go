package ldap

import (
	"context"
	"fmt"

	"github.com/azdharsyahputra/openmail/internal/identity"
	goldap "github.com/go-ldap/ldap/v3"
)

func (p *Provider) Groups(ctx context.Context, username string) ([]identity.Group, error) {
	user, err := p.Lookup(ctx, username)
	if err != nil {
		return nil, err
	}

	userDN := user.Attributes["dn"]
	groupFilter, err := BuildGroupFilter(p.cfg.GroupFilter, userDN, user.Username)
	if err != nil {
		return nil, err
	}

	entries, err := p.client.Search(ctx, p.cfg.GroupBaseDN, groupFilter, goldap.ScopeWholeSubtree, []string{"cn", "description", "member", "uniqueMember"})
	if err != nil {
		return nil, fmt.Errorf("group lookup error: %w", err)
	}

	var groups []identity.Group
	for _, entry := range entries {
		cn := entry.GetAttributeValue("cn")
		desc := entry.GetAttributeValue("description")
		members := append(entry.GetAttributeValues("member"), entry.GetAttributeValues("uniqueMember")...)

		groups = append(groups, identity.Group{
			ID:          cn,
			Name:        cn,
			DN:          entry.DN,
			Description: desc,
			Members:     members,
		})
	}

	return groups, nil
}
