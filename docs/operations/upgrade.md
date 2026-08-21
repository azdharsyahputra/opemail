# MailOpen Operations Runbook: Upgrade & Migration

## 1. Pre-Upgrade Safeguards
Always take an encrypted snapshot before performing upgrades:
```bash
mailopen backup create /var/backups/mailopen-pre-upgrade.enc --passphrase "$BACKUP_PASSPHRASE"
```

## 2. Binary Replacement
Download and verify release binary:
```bash
wget https://github.com/azdharsyahputra/openmail/releases/download/v0.9.0/mailopen-linux-amd64
sha256sum -c SHA256SUMS
chmod +x mailopen-linux-amd64
sudo mv mailopen-linux-amd64 /usr/local/bin/mailopen
```

## 3. Database Schema Migration
Execute sequential schema migrations:
```bash
mailopen migrate up
```

## 4. Subsystem Reload & Validation
Reload Postfix and Dovecot:
```bash
mailopen postfix reload
mailopen dovecot reload
mailopen system doctor
```

## 5. Rollback Procedure
If migration fails, transactions are automatically rolled back. To restore from snapshot:
```bash
mailopen backup restore /var/backups/mailopen-pre-upgrade.enc --passphrase "$BACKUP_PASSPHRASE" --target /
```
