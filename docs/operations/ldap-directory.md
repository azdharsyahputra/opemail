# MailOpen Operations Runbook: LDAP Identity & Directory Integration (W3.1)

## 1. Architecture Overview

MailOpen separates Identity & Authentication from Mail Storage & Metadata:

```text
                         MAILOPEN
                            │
                  ┌─────────▼─────────┐
                  │  Identity Layer   │
                  └─────────┬─────────┘
                            │
              ┌─────────────┴─────────────┐
              │                           │
       Local Identity                  LDAP Identity
       PostgreSQL                      OpenLDAP / Active Directory
              │                           │
              └─────────────┬─────────────┘
                            │
                     Identity Service
                            │
             ┌──────────────┼──────────────┐
             ▼              ▼              ▼
          Dovecot        Submission       Admin API
             │              │                │
             └──────────────┴────────────────┘
                            │
                       PostgreSQL
                 (Mail State / Mailbox DB)
```

## 2. Directory Schema & Attributes

| Attribute | Meaning | Mapping in MailOpen |
|---|---|---|
| `uid` / `sAMAccountName` | Username identifier | `Identity.Username` |
| `mail` / `userPrincipalName` | Primary email address | `Identity.Email` / `mailboxes.email` |
| `cn` / `displayName` | Full name | `Identity.DisplayName` |
| `givenName` / `sn` | First and last name | `Identity.FirstName`, `Identity.LastName` |
| `memberOf` | Group memberships | RBAC roles (`mail-admins` $\rightarrow$ `admin`, `mail-operators` $\rightarrow$ `operator`) |
| `accountStatus` / `nsAccountLock` | Status flag | When `disabled` or `locked`, authentication is rejected immediately |

## 3. Account Gatekeeper Security Rule

Even when an LDAP user authenticates successfully with valid credentials:
- A matching record must exist in PostgreSQL `mailboxes`
- The mailbox `status` must be `active`
- The mailbox `provisioning_status` must be `ready`

If an LDAP user has no provisioned mailbox in PostgreSQL, mail access is **denied (`451` / `535`)**.

## 4. CLI Operations

### LDAP Diagnostics
```bash
mailopen ldap doctor
```

### Direct Identity Authentication Test
```bash
mailopen identity auth ajar@example.com --password-stdin
```

### Synchronize LDAP Identities to Mailboxes
```bash
# Preview sync in dry-run mode
mailopen identity sync --domain example.com --dry-run

# Provision mailboxes for discovered identities
mailopen identity sync --domain example.com --auto-create
```
