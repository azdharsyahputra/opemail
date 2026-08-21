package ldap

import (
	"strings"

	"github.com/azdharsyahputra/openmail/internal/identity"
	goldap "github.com/go-ldap/ldap/v3"
)

type Mapper struct {
	groupRoleMapping map[string]string
}

func NewMapper(groupRoleMapping map[string]string) *Mapper {
	if groupRoleMapping == nil {
		groupRoleMapping = map[string]string{
			"mail-admins":    "admin",
			"mail-operators": "operator",
			"mail-auditors":  "auditor",
		}
	}
	return &Mapper{groupRoleMapping: groupRoleMapping}
}

func (m *Mapper) EntryToIdentity(entry *goldap.Entry) *identity.Identity {
	if entry == nil {
		return nil
	}

	uid := entry.GetAttributeValue("uid")
	if uid == "" {
		uid = entry.GetAttributeValue("sAMAccountName")
	}

	mail := entry.GetAttributeValue("mail")
	if mail == "" {
		mail = entry.GetAttributeValue("userPrincipalName")
	}
	if mail == "" && strings.Contains(uid, "@") {
		mail = uid
	}

	displayName := entry.GetAttributeValue("displayName")
	if displayName == "" {
		displayName = entry.GetAttributeValue("cn")
	}

	firstName := entry.GetAttributeValue("givenName")
	lastName := entry.GetAttributeValue("sn")

	// Determine status from LDAP account controls / lock attributes
	status := identity.StatusActive
	if strings.EqualFold(entry.GetAttributeValue("nsAccountLock"), "true") ||
		strings.EqualFold(entry.GetAttributeValue("accountStatus"), "disabled") ||
		strings.EqualFold(entry.GetAttributeValue("accountStatus"), "locked") {
		status = identity.StatusDisabled
	}

	attributes := make(map[string]string)
	for _, attr := range entry.Attributes {
		if len(attr.Values) > 0 {
			attributes[attr.Name] = attr.Values[0]
		}
	}
	attributes["dn"] = entry.DN

	// Parse groups if memberOf is populated
	var groups []string
	var roles []identity.Role
	memberOf := entry.GetAttributeValues("memberOf")
	for _, groupDN := range memberOf {
		cn := extractCNFromDN(groupDN)
		if cn != "" {
			groups = append(groups, cn)
			if roleStr, exists := m.groupRoleMapping[cn]; exists {
				roles = append(roles, identity.Role(roleStr))
			}
		}
	}

	if len(roles) == 0 {
		roles = append(roles, identity.RoleUser)
	}

	return &identity.Identity{
		ID:          entry.DN,
		Username:    uid,
		Email:       strings.ToLower(mail),
		DisplayName: displayName,
		FirstName:   firstName,
		LastName:    lastName,
		Status:      status,
		Provider:    "ldap",
		Attributes:  attributes,
		Groups:      groups,
		Roles:       roles,
	}
}

func extractCNFromDN(dn string) string {
	parts := strings.Split(dn, ",")
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToLower(trimmed), "cn=") {
			return trimmed[3:]
		}
	}
	return dn
}
