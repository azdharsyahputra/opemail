# W2.5 — Dovecot IMAP + Authentication

## 0. Target Akhir W2.5

Sebelum W2.5:
```text
SMTP -> Postfix -> Maildir
```

Setelah W2.5:
```text
                         MailOpen
                            │
                       PostgreSQL
                     ┌──────┴──────┐
                     │             │
                  Postfix        Dovecot
                     │             │
                   SMTP           IMAP
                     │             │
                     └──────┬──────┘
                            ▼
                    /var/vmail/...
                            │
                            ▼
                         Maildir
```

Client (Outlook / Thunderbird / Webmail):
```text
Outlook / Thunderbird
        │
        │ IMAP (:143)
        ▼
     Dovecot
        │
        ├── Authentication
        │       ↓
        │   PostgreSQL (mailboxes.password_hash)
        │       ↓
        │   Argon2id verification
        │
        └── Mailbox access
                ↓
             Maildir++ (/var/vmail/<domain>/<localpart>/Maildir)
```

## Definition of Done W2.5

- [x] Architecture
  - [x] Dovecot separated from MailOpen domain layer
  - [x] PostgreSQL source of truth
  - [x] Dedicated read-only DB role (`mailopen_dovecot`)
  - [x] Maildir remains live storage (`vmail:vmail`, 5000:5000, 0750)
- [x] Authentication
  - [x] PostgreSQL passdb (Argon2id)
  - [x] Case-insensitive username canonicalization
  - [x] `active` required
  - [x] `provisioning_status = 'ready'` required
  - [x] Wrong password rejected (generic error, no enumeration)
  - [x] Unknown user rejected
  - [x] Suspended user rejected
- [x] Userdb
  - [x] UID 5000, GID 5000
  - [x] Maildir derived from domain/localpart (`/var/vmail/%d/%n/Maildir`)
  - [x] No mailbox path stored in DB
- [x] IMAP
  - [x] IMAP :143
  - [x] LOGIN
  - [x] SELECT INBOX
  - [x] SEARCH
  - [x] FETCH headers
  - [x] FETCH body (reads email delivered in W2.4)
  - [x] LOGOUT
- [x] Filesystem
  - [x] Maildir readable/writable by Dovecot
  - [x] Ownership `vmail:vmail` (5000:5000)
  - [x] Privilege separation maintained
- [x] Config
  - [x] `mailopen dovecot config generate`
  - [x] `mailopen dovecot config validate`
  - [x] Atomic deployment (`0640` credentials)
  - [x] Reload only on config changes
- [x] Doctor
  - [x] `mailopen dovecot doctor`
  - [x] `mailopen dovecot lookup user <email>`
  - [x] `mailopen dovecot auth test <email> --password "<pass>"`
- [x] E2E
  - [x] SMTP :25 -> Postfix -> Maildir -> Dovecot -> IMAP :143 -> Message fetched!
