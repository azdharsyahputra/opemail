# MailOpen Operations Runbook: Disaster Recovery (DR)

## 1. DR SLA & Targets
- **Recovery Point Objective (RPO)**: $\le 15\text{ minutes}$ (Interval between incremental/full snapshots)
- **Recovery Time Objective (RTO)**: $\le 30\text{ minutes}$ (Total time from bare-metal bootstrap to operational health)

## 2. Bare-Metal Cross-Host Recovery Workflow
1. Provision clean host with Debian / Ubuntu.
2. Install dependencies (`postgresql`, `postfix`, `dovecot-imapd`, `opendkim`, `mailopen`).
3. Restore backup payload:
   ```bash
   mailopen backup restore /mnt/storage/mailopen-latest.enc --passphrase "$PASSPHRASE" --target /
   ```
4. Re-import database tables:
   ```bash
   mailopen migrate up
   ```
5. Run full system diagnostics:
   ```bash
   mailopen system doctor
   ```
6. Verify live protocol connectivity:
   - Inbound SMTP (:25)
   - Outbound Submission (:587)
   - IMAP (:143) / IMAPS (:993)
