# MailOpen Operations Runbook: Backup & Restore

## 1. Automated Encrypted Backups
MailOpen generates AES-256-GCM encrypted snapshot archives containing:
- PostgreSQL database table dumps
- Maildir message storage
- DKIM private keys (`0600` permissions preserved)
- TLS certificates and private keys
- Subsystem configuration files

### Create Backup
```bash
mailopen backup create /var/backups/mailopen-$(date +%Y%m%d).enc --passphrase "$BACKUP_PASSPHRASE"
```

## 2. Integrity Verification
Verify archive without extraction:
```bash
mailopen backup verify /var/backups/mailopen-$(date +%Y%m%d).enc --passphrase "$BACKUP_PASSPHRASE"
```

## 3. Restore Procedure
```bash
mailopen backup restore /var/backups/mailopen-snapshot.enc --passphrase "$BACKUP_PASSPHRASE" --target /
```

Post-restore validation:
```bash
mailopen system doctor
```
