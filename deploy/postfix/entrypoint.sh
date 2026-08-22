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
postconf -e "smtp_tls_security_level=may" 2>/dev/null || true
postconf -e "smtp_tls_loglevel=1" 2>/dev/null || true
postconf -e "smtp_tls_protocols=>=TLSv1.2" 2>/dev/null || true
postconf -e "smtp_tls_ciphers=medium" 2>/dev/null || true
postconf -e "smtp_tls_CAfile=/etc/ssl/certs/ca-certificates.crt" 2>/dev/null || true
postconf -e "smtp_tls_CApath=/etc/ssl/certs" 2>/dev/null || true
postconf -e "mynetworks=127.0.0.0/8 [::1]/128 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16" 2>/dev/null || true
postconf -e "smtpd_relay_restrictions=permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination" 2>/dev/null || true
postconf -e "smtpd_recipient_restrictions=permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination" 2>/dev/null || true

# Prepare opendkim runtime directories & socket path
mkdir -p /var/run/opendkim /var/spool/postfix/private /etc/opendkim
chown -R postfix:postfix /var/run/opendkim /var/spool/postfix/private /etc/opendkim 2>/dev/null || true
chmod 0770 /var/run/opendkim 2>/dev/null || true
chmod 0750 /var/spool/postfix/private 2>/dev/null || true

# Auto-generate OpenDKIM config and tables inside /etc/opendkim
mkdir -p /etc/opendkim/keys /var/run/opendkim /var/spool/postfix/private
cat << 'EOF' > /etc/opendkim/opendkim.conf
AutoRestart             Yes
AutoRestartRate         10/1h
UMask                   002
Syslog                  Yes
SyslogSuccess           Yes
LogWhy                  Yes
RequireSafeKeys         No

Canonicalization        relaxed/relaxed
Mode                    sv
SubDomains              yes

Socket                  local:/var/spool/postfix/private/opendkim
PidFile                 /var/run/opendkim/opendkim.pid
UserID                  postfix:postfix

KeyTable                /etc/opendkim/KeyTable
SigningTable            /etc/opendkim/SigningTable
ExternalIgnoreList      /etc/opendkim/TrustedHosts
InternalHosts           /etc/opendkim/TrustedHosts
EOF

cat << 'EOF' > /etc/opendkim/TrustedHosts
127.0.0.1
::1
localhost
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
EOF

> /etc/opendkim/KeyTable
> /etc/opendkim/SigningTable

# Copy and secure active private.key for each domain into /etc/opendkim/keys
for dom_dir in /etc/mailopen/dkim/*; do
    if [ -d "$dom_dir" ]; then
        dom=$(basename "$dom_dir")
        if [ "$dom" = "*" ] || [ -z "$dom" ]; then continue; fi
        
        # Prefer 'mail' selector if exists, otherwise latest directory
        if [ -f "$dom_dir/mail/private.key" ]; then
            sel="mail"
        else
            sel=$(ls -1t "$dom_dir" 2>/dev/null | head -n 1)
        fi
        
        if [ -n "$sel" ] && [ -f "$dom_dir/$sel/private.key" ]; then
            mkdir -p "/etc/opendkim/keys/${dom}/${sel}"
            cp "$dom_dir/$sel/private.key" "/etc/opendkim/keys/${dom}/${sel}/private.key" 2>/dev/null || true
            chown -R postfix:postfix "/etc/opendkim/keys/${dom}" 2>/dev/null || true
            chmod 0600 "/etc/opendkim/keys/${dom}/${sel}/private.key" 2>/dev/null || true
            echo "${sel}._domainkey.${dom} ${dom}:${sel}:/etc/opendkim/keys/${dom}/${sel}/private.key" >> /etc/opendkim/KeyTable
            echo "*@${dom} ${sel}._domainkey.${dom}" >> /etc/opendkim/SigningTable
            echo "${dom} ${sel}._domainkey.${dom}" >> /etc/opendkim/SigningTable
        fi
    fi
done

chown -R postfix:postfix /etc/opendkim /var/spool/postfix/private /var/run/opendkim 2>/dev/null || true
find /etc/opendkim -type d -exec chmod 0755 {} + 2>/dev/null || true
find /etc/opendkim -type f -exec chmod 0640 {} + 2>/dev/null || true
find /etc/opendkim/keys -type f -exec chmod 0600 {} + 2>/dev/null || true

# Start OpenDKIM daemon
echo "Starting OpenDKIM milter daemon..."
rm -f /var/run/opendkim/opendkim.pid /var/spool/postfix/private/opendkim
opendkim -x /etc/opendkim/opendkim.conf -p local:/var/spool/postfix/private/opendkim -u postfix:postfix || true

# Start Postfix in foreground
exec postfix start-fg
