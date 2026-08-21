package ldap

import (
	"strings"
	"unicode/utf8"

	"github.com/azdharsyahputra/openmail/internal/identity"
	goldap "github.com/go-ldap/ldap/v3"
)

const maxAttrBytes = 4096

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

	uid := sanitizeString(entry.GetAttributeValue("uid"))
	if uid == "" {
		uid = sanitizeString(entry.GetAttributeValue("sAMAccountName"))
	}

	// Pick first valid canonical email
	mailValues := entry.GetAttributeValues("mail")
	var mail string
	for _, mv := range mailValues {
		san := sanitizeString(mv)
		if san != "" && strings.Contains(san, "@") {
			mail = san
			break
		}
	}
	if mail == "" {
		mail = sanitizeString(entry.GetAttributeValue("userPrincipalName"))
	}
	if mail == "" && strings.Contains(uid, "@") {
		mail = uid
	}

	displayName := sanitizeString(entry.GetAttributeValue("displayName"))
	if displayName == "" {
		displayName = sanitizeString(entry.GetAttributeValue("cn"))
	}

	firstName := sanitizeString(entry.GetAttributeValue("givenName"))
	lastName := sanitizeString(entry.GetAttributeValue("sn"))

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
			attributes[attr.Name] = sanitizeString(attr.Values[0])
		}
	}
	attributes["dn"] = sanitizeString(entry.DN)

	// Parse groups if memberOf is populated (deduplicated)
	groupMap := make(map[string]bool)
	roleMap := make(map[identity.Role]bool)
	var groups []string
	var roles []identity.Role

	memberOf := entry.GetAttributeValues("memberOf")
	for _, groupDN := range memberOf {
		cn := extractCNFromDN(sanitizeString(groupDN))
		if cn != "" && !groupMap[cn] {
			groupMap[cn] = true
			groups = append(groups, cn)
			if roleStr, exists := m.groupRoleMapping[cn]; exists {
				r := identity.Role(roleStr)
				if !roleMap[r] {
					roleMap[r] = true
					roles = append(roles, r)
				}
			}
		}
	}

	if len(roles) == 0 {
		roles = append(roles, identity.RoleUser)
	}

	return &identity.Identity{
		ID:          sanitizeString(entry.DN),
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

func sanitizeString(s string) string {
	if !utf8.ValidString(s) {
		// Replace invalid UTF-8 sequences
		s = strings.ToValidUTF8(s, "")
	}
	if len(s) > maxAttrBytes {
		s = s[:maxAttrBytes]
	}
	return strings.TrimSpace(s)
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
