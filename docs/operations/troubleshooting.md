# MailOpen Operations Runbook: Troubleshooting

## 1. Diagnostic Decision Tree: "External Mail Delivery Issues"

```text
External Client (e.g. Gmail) Rejection / Spam
                      │
                      ▼
            mailopen system doctor
                      │
        ┌─────────────┴─────────────┐
     HEALTHY                     UNHEALTHY
        │                            │
        ▼                            ▼
  mailopen queue status        Fix reported failures
        │
  mailopen domain doctor <domain>
        │
        ├── SPF alignment
        ├── DKIM DNS key match (mailopen dkim verify <domain>)
        ├── DMARC policy & alignment
        ├── TLS certificate validity
        └── Reverse DNS (PTR & FCrDNS)
```

## 2. Common Symptoms & Fixes

### Symptom: Postfix Relay Access Denied (`554`)
- **Cause**: Outbound client connecting to :25 without authentication, or local sender trying to relay without STARTTLS & SASL.
- **Fix**: Direct outbound mail clients to port **:587** with STARTTLS enabled and SMTP AUTH.

### Symptom: Temporary Lookup Error (`451 4.3.0`)
- **Cause**: PostgreSQL connection failure.
- **Fix**: Check `systemctl status postgresql` or verify `DATABASE_URL`.

### Symptom: Authentication Failed (`535 5.7.8` / `NO [AUTHENTICATIONFAILED]`)
- **Cause**: Incorrect password, suspended mailbox, or mailbox in pending provisioning state.
- **Fix**: Check `mailopen mailbox inspect <email>` and ensure status is `ready`.
