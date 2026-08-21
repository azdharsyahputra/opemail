# MailOpen Operations Runbook: Incident Response

## Severity Classification

| Level | Definition | SLA Response |
|---|---|---|
| **P0 - Critical** | Total mail flow stoppage, database corruption, or open relay compromise | $\le 15\text{ minutes}$ |
| **P1 - High** | Outbound mail marked as spam, deferred queue backlog spiking | $\le 1\text{ hour}$ |
| **P2 - Medium** | Single user delivery issue, quota reconciliation discrepancy | $\le 4\text{ hours}$ |

## Emergency Actions

### Immediate Open Relay Containment
```bash
# Verify relay restrictions
mailopen postfix config validate
# Force restart with strict defaults
systemctl restart postfix
```

### Urgent Queue Flush / Retry
```bash
mailopen queue retry all
```

### Catastrophic Database Loss
```bash
mailopen backup restore /var/backups/mailopen-latest.enc --passphrase "$PASSPHRASE" --target /
```
