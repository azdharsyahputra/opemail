# MailOpen Operations Runbook: Clean Installation

## 1. Prerequisites
- **OS**: Debian 12 / Ubuntu 22.04 LTS / macOS Darwin
- **RAM**: Minimum 4 GB (8 GB recommended for production)
- **Disk**: Minimum 20 GB SSD
- **Network**: Inbound ports open for TCP :25 (SMTP), :587 (Submission), :143 (IMAP STARTTLS), :993 (IMAPS)

## 2. Dependencies
Ensure the following packages are installed:
```bash
apt-get update && apt-get install -y \
  postgresql postgresql-contrib \
  postfix postfix-pgsql \
  dovecot-core dovecot-imapd dovecot-pgsql \
  opendkim opendkim-tools \
  rspamd clamav-daemon
```

## 3. Database Initialization
```bash
sudo -u postgres psql -c "CREATE USER mailopen WITH PASSWORD 'YourStrongPassword';"
sudo -u postgres psql -c "CREATE DATABASE mailopen OWNER mailopen;"
```

Run MailOpen database migrations:
```bash
DATABASE_URL="postgres://mailopen:YourStrongPassword@127.0.0.1:5432/mailopen?sslmode=disable" mailopen migrate up
```

## 4. Subsystem Provisioning
Generate standard configurations:
```bash
mailopen postfix config generate
mailopen dovecot config generate
mailopen system doctor
```

## 5. Domain & Mailbox Bootstrap
```bash
mailopen domain create example.com
mailopen dkim generate example.com --selector default
mailopen tls install example.com --cert /etc/ssl/certs/fullchain.pem --key /etc/ssl/private/privkey.pem
mailopen mailbox create ajar@example.com --password-stdin
```

Run comprehensive diagnostics:
```bash
mailopen system doctor
```
Expected output: `Result: HEALTHY`.
