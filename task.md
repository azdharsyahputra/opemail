# W2.6 — SMTP Submission :587 + SMTP AUTH

## 0. Definition of Done

Setelah W2.6:
```text
                    MAIL CLIENT
                 Outlook / Thunderbird
                         │
                         │ SMTP Submission
                         │ TCP :587
                         ▼
                ┌─────────────────┐
                │     Postfix     │
                │  submission     │
                └────────┬────────┘
                         │
                     SMTP AUTH
                         │
                         ▼
                    Dovecot SASL
                         │
                         ▼
                    PostgreSQL
                         │
                    Argon2id
                         │
                         ▼
                  authenticated
                         │
                         ▼
                    Postfix Queue
                         │
                         ▼
                      Internet / Local Maildir
```

Inbound (:25) tetap:
```text
Internet -> Postfix :25 (No AUTH) -> Maildir -> Dovecot -> IMAP :143
```

## Definition of Done Checklist

- [x] SMTP
  - [x] :25 inbound tetap bekerja
  - [x] :25 open relay tetap blocked
  - [x] :25 SMTP AUTH disabled
- [x] Submission
  - [x] :587 listening
  - [x] :587 SMTP AUTH enabled
  - [x] Authenticated submission works
  - [x] Unauthenticated submission blocked
- [x] Authentication
  - [x] Dovecot SASL via Unix socket
  - [x] PostgreSQL single source of truth
  - [x] Argon2id verification
  - [x] `active` + `ready` required
  - [x] Wrong password rejected (535)
  - [x] Suspended rejected
  - [x] Pending rejected
- [x] Sender Policy
  - [x] Primary sender works (`ajar@example.com`)
  - [x] Authorized alias works (`support@example.com`)
  - [x] Unauthorized/spoofed sender rejected (`553 Sender address rejected`)
- [x] Delivery
  - [x] Authenticated -> local mailbox (delivered to Maildir)
  - [x] Authenticated -> outbound queue (queued for remote delivery)
  - [x] Queue ID generated
- [x] Security
  - [x] No plaintext credentials in logs
  - [x] Read-only DB role (`mailopen_dovecot`)
  - [x] SASL socket permissions safe (0660 / private)
  - [x] No public SASL socket
  - [x] Connection limits & baseline rate-limiting configured
- [x] CLI & Doctor
  - [x] `mailopen postfix submission config generate`
  - [x] `mailopen postfix submission config validate`
  - [x] `mailopen postfix submission doctor`
  - [x] `mailopen postfix submission auth-test <email> --password "<pass>"`
- [x] E2E
  - [x] SMTP AUTH :587
  - [x] MAIL FROM
  - [x] RCPT TO
  - [x] DATA
  - [x] Queue generated
  - [x] Local delivery to Maildir
  - [x] IMAP sees submitted local message
