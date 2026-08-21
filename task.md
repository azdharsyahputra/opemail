# W2.8 — Mail Identity, DKIM Signing, SPF & DMARC

## 0. Target Architecture

```text
                         INTERNET
                            │
             ┌──────────────┴──────────────┐
             │                             │
          INBOUND                       OUTBOUND
             │                             │
             ▼                             ▼
        Postfix :25                  Postfix :587
             │                             │
             │                         STARTTLS
             │                             │
             │                         SMTP AUTH
             │                             │
             │                             ▼
             │                       Outbound Queue
             │                             │
             │                             ▼
             │                         OpenDKIM (milter)
             │                             │
             │                       DKIM Signature (d=example.com, s=mailopen2026)
             │                             │
             └──────────────┬──────────────┘
                            │
                            ▼
                         Internet
                            │
                 ┌──────────┼──────────┐
                 ▼          ▼          ▼
                SPF       DKIM       DMARC
```

MailOpen Control Plane:
- **Domain**: SPF policy, DKIM selector, DMARC policy
- **DKIM Key Manager**: Generate, rotate, activate, revoke
- **DNS Verification & Doctor**: SPF, DKIM, DMARC

---

## 1. Definition of Done Checklist

- [ ] **W2.8.1 DKIM Domain Model + Database Migrations**
  - [ ] Migration `000006_dkim.up.sql` (tables `domain_dkim` & `domain_mail_policy`)
  - [ ] Migration `000006_dkim.down.sql`
  - [ ] Model `DKIMKey`, `DKIMStatus` (pending, active, revoked), `DomainMailPolicy`
  - [ ] Repository interface and PostgreSQL implementation
- [ ] **W2.8.2 Secure DKIM Keystore**
  - [ ] Storage path `/etc/mailopen/dkim/<domain>/<selector>/private.key` (NOT in PostgreSQL)
  - [ ] Directory permissions `0750`, private key permissions `0600`
  - [ ] Atomic private key installation (`.tmp` -> `fsync` -> `chmod 0600` -> `rename`)
- [ ] **W2.8.3 RSA-2048 Key Generation & Public DNS Record**
  - [ ] Cryptographic RSA-2048 generation
  - [ ] Base64 DER public key extraction
  - [ ] DNS TXT format `v=DKIM1; k=rsa; p=PUBLIC_KEY`
- [ ] **W2.8.4 Selector Validation & Lifecycle**
  - [ ] Selector format validation `^[a-z0-9][a-z0-9._-]{0,62}$` (rejects path traversal `../`)
  - [ ] Lifecycle: generate -> pending -> DNS verified -> active -> rotated -> revoked
- [ ] **W2.8.5 OpenDKIM Provisioning & Milter Integration**
  - [ ] OpenDKIM config generator (`opendkim.conf`, `KeyTable`, `SigningTable`, `TrustedHosts`)
  - [ ] Unix socket `/var/spool/postfix/private/opendkim`
  - [ ] Postfix `smtpd_milters` & `non_smtpd_milters` integration
- [ ] **W2.8.6 SPF & DMARC Policies**
  - [ ] SPF policy generator & syntax validator (`v=spf1 ...`)
  - [ ] DMARC policy generator & syntax validator (`v=DMARC1; p=none ...`)
  - [ ] Domain mail policy persistence in PostgreSQL
- [ ] **W2.8.7 DNS Verification & Domain Doctor**
  - [ ] DKIM DNS verification against local public key
  - [ ] SPF DNS verification
  - [ ] DMARC DNS verification
  - [ ] `mailopen domain doctor <domain>` comprehensive report
- [ ] **W2.8.8 CLI Subcommands**
  - [ ] `mailopen dkim key generate <domain>`
  - [ ] `mailopen dkim key list <domain>`
  - [ ] `mailopen dkim key activate <domain> <selector>`
  - [ ] `mailopen dkim key revoke <domain> <selector>`
  - [ ] `mailopen dkim verify <domain>`
  - [ ] `mailopen dkim doctor <domain>`
  - [ ] `mailopen domain spf show / set / verify <domain>`
  - [ ] `mailopen domain dmarc show / set / verify <domain>`
  - [ ] `mailopen domain doctor <domain>`
  - [ ] `mailopen postfix dkim status`
- [ ] **W2.8.9 Test Matrices & E2E Outbound DKIM Signing**
  - [ ] Unit tests for keygen, keystore, selector validation, SPF/DMARC parsers
  - [ ] `tests/dkim_integration_test.go`:
    - [ ] Keygen & keystore file permissions (`0600`/`0750`)
    - [ ] OpenDKIM milter signing on :587 submission
    - [ ] Raw message contains valid `DKIM-Signature` (`d=`, `s=`, `a=rsa-sha256`)
    - [ ] Sender authorization integration
    - [ ] Key rotation & revocation safety
  - [ ] `tests/dns_integration_test.go`:
    - [ ] SPF & DMARC validation
    - [ ] Domain Doctor report
