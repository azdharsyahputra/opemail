# Mail Identity, DKIM Signing, SPF & DMARC Architecture

## 1. Overview & Architecture

MailOpen implements a secure, standards-compliant email authentication and deliverability stack:

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
             │                         STARTTLS (Mandatory)
             │                             │
             │                         SMTP AUTH (Dovecot SASL)
             │                             │
             │                             ▼
             │                       Outbound Queue
             │                             │
             │                             ▼
             │                         OpenDKIM (Milter)
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

---

## 2. Security & Keystore Principles

1. **No Private Keys in PostgreSQL**:
   - PostgreSQL only stores metadata in `domain_dkim` (`id`, `domain_id`, `selector`, `algorithm`, `key_bits`, `status`, `created_at`, `activated_at`, `revoked_at`).
   - Private keys are stored in the filesystem at `/etc/mailopen/dkim/<domain>/<selector>/private.key`.
   - File permissions: Directory `0750`, Private key `0600`.
   - OpenDKIM accesses the private keys directly from filesystem via read-only mount. OpenDKIM has **no direct database access**.

2. **Atomic Installation & Rollback**:
   - Key generation uses cryptographic RSA-2048 (`rsa-sha256`).
   - Writing keys to disk uses temporary files (`.tmp`), `fsync`, `chmod 0600`, and atomic `rename`.

3. **Selector Lifecycle**:
   - `generate` $\rightarrow$ status `pending`.
   - `verify` $\rightarrow$ checks DNS TXT record `v=DKIM1; k=rsa; p=...` against local public key.
   - `activate` $\rightarrow$ status `active` for outbound signing.
   - `rotate` $\rightarrow$ create new selector (e.g. `mailopen2027`), publish DNS, verify, activate new, then `revoke` old key.

---

## 3. Postfix & OpenDKIM Milter Integration

- **Unix Socket**: OpenDKIM listens on `/var/spool/postfix/private/opendkim` (mode `0660`, user `postfix:postfix`).
- **Postfix Configuration (`main.cf`)**:
  ```text
  smtpd_milters = unix:private/opendkim
  non_smtpd_milters = unix:private/opendkim
  milter_default_action = accept
  milter_protocol = 6
  ```

---

## 4. SPF & DMARC Policies

- **SPF**:
  - Default: `v=spf1 mx ~all`
  - Fully customizable per domain via PostgreSQL `domain_mail_policy`.
- **DMARC**:
  - Default: `v=DMARC1; p=none; rua=mailto:dmarc@<domain>` (Observation phase).
  - Supports strict modes: `p=quarantine`, `p=reject`, `adkim=s`, `aspf=s`, `pct=100`.

---

## 5. CLI Reference

### DKIM Management
```bash
# Generate a new DKIM key for domain
mailopen dkim key generate example.com --selector mailopen2026

# List DKIM keys for domain
mailopen dkim key list example.com

# Verify DKIM DNS record publication & local key match
mailopen dkim verify example.com --selector mailopen2026

# Activate DKIM key for signing
mailopen dkim key activate example.com mailopen2026

# Revoke DKIM key
mailopen dkim key revoke example.com mailopen2026

# Run DKIM Doctor diagnostics
mailopen dkim doctor example.com
```

### SPF & DMARC Management
```bash
# Show SPF policy
mailopen domain spf show example.com

# Set custom SPF policy
mailopen domain spf set example.com --policy "v=spf1 mx ip4:203.0.113.10 -all"

# Verify SPF DNS record
mailopen domain spf verify example.com

# Show DMARC policy
mailopen domain dmarc show example.com

# Set custom DMARC policy
mailopen domain dmarc set example.com --policy "v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc@example.com"

# Verify DMARC DNS record
mailopen domain dmarc verify example.com

# Run full Mail Domain Doctor
mailopen domain doctor example.com
```

### Postfix OpenDKIM Milter
```bash
# Check OpenDKIM milter socket status
mailopen postfix dkim status

# Generate OpenDKIM config, KeyTable, SigningTable, and TrustedHosts
mailopen postfix dkim generate
```
