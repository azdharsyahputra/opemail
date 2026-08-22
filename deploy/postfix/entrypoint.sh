#!/bin/bash
set -e

# If config volume mounted at /config, copy all config files into /etc/postfix
if [ -d "/config" ]; then
    cp -a /config/*.cf /etc/postfix/ 2>/dev/null || true
    chgrp postfix /etc/postfix/*.cf 2>/dev/null || true
    chmod 0640 /etc/postfix/*.cf 2>/dev/null || true
fi

# Ensure /var/vmail exists and has correct ownership (vmail:vmail 5000:5000 0750)
mkdir -p /var/vmail
chown -R vmail:vmail /var/vmail 2>/dev/null || true
chmod 0750 /var/vmail 2>/dev/null || true

# Fix postfix permissions & generate aliases db if needed
postfix set-permissions 2>/dev/null || true
newaliases 2>/dev/null || true

# Always enforce outbound TLS encryption for delivering to Google / external MTAs
postconf -e "smtp_tls_security_level=may" \
            "smtp_tls_loglevel=1" \
            "smtp_tls_protocols=>=TLSv1.2" \
            "smtp_tls_ciphers=medium" \
            "smtp_tls_CAfile=/etc/ssl/certs/ca-certificates.crt" \
            "smtp_tls_CApath=/etc/ssl/certs" 2>/dev/null || true

# Prepare opendkim runtime directories & socket path
mkdir -p /var/run/opendkim /var/spool/postfix/private /etc/mailopen/opendkim /etc/mailopen/dkim
chown -R postfix:postfix /var/run/opendkim /var/spool/postfix/private 2>/dev/null || true
chmod 0770 /var/run/opendkim 2>/dev/null || true
chmod 0750 /var/spool/postfix/private 2>/dev/null || true

# Auto-generate OpenDKIM config and tables by scanning /etc/mailopen/dkim
mkdir -p /etc/mailopen/opendkim
cat << 'EOF' > /etc/mailopen/opendkim/opendkim.conf
AutoRestart             Yes
AutoRestartRate         10/1h
UMask                   002
Syslog                  Yes
SyslogSuccess           Yes
LogWhy                  Yes

Canonicalization        relaxed/simple
Mode                    sv
SubDomains              yes

Socket                  local:/var/spool/postfix/private/opendkim
PidFile                 /var/run/opendkim/opendkim.pid
UserID                  postfix:postfix

KeyTable                /etc/mailopen/opendkim/KeyTable
SigningTable            refile:/etc/mailopen/opendkim/SigningTable
ExternalIgnoreList      /etc/mailopen/opendkim/TrustedHosts
InternalHosts           /etc/mailopen/opendkim/TrustedHosts
EOF

cat << 'EOF' > /etc/mailopen/opendkim/TrustedHosts
127.0.0.1
::1
localhost
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
EOF

> /etc/mailopen/opendkim/KeyTable
> /etc/mailopen/opendkim/SigningTable

# Scan all private.key files in /etc/mailopen/dkim
for key_file in $(find /etc/mailopen/dkim -name "private.key" 2>/dev/null); do
    sel=$(basename $(dirname "$key_file"))
    dom=$(basename $(dirname $(dirname "$key_file")))
    if [ -n "$dom" ] && [ -n "$sel" ] && [ "$dom" != "." ]; then
        echo "${sel}._domainkey.${dom} ${dom}:${sel}:${key_file}" >> /etc/mailopen/opendkim/KeyTable
        echo "*@${dom} ${sel}._domainkey.${dom}" >> /etc/mailopen/opendkim/SigningTable
        echo "${dom} ${sel}._domainkey.${dom}" >> /etc/mailopen/opendkim/SigningTable
    fi
done

chown -R postfix:postfix /etc/mailopen/opendkim /var/spool/postfix/private 2>/dev/null || true
chmod 0640 /etc/mailopen/opendkim/* 2>/dev/null || true

# Start OpenDKIM daemon
echo "Starting OpenDKIM milter daemon..."
rm -f /var/run/opendkim/opendkim.pid /var/spool/postfix/private/opendkim
opendkim -x /etc/mailopen/opendkim/opendkim.conf || true


# Start Postfix in foreground
exec postfix start-fg
