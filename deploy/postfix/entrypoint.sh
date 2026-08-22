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
mkdir -p /var/run/opendkim /var/spool/postfix/private
chown -R postfix:postfix /var/run/opendkim /var/spool/postfix/private 2>/dev/null || true
chmod 0770 /var/run/opendkim 2>/dev/null || true
chmod 0750 /var/spool/postfix/private 2>/dev/null || true

# Start OpenDKIM if config exists
if [ -f "/etc/mailopen/opendkim/opendkim.conf" ]; then
    echo "Starting OpenDKIM..."
    rm -f /var/run/opendkim/opendkim.pid /var/spool/postfix/private/opendkim
    opendkim -x /etc/mailopen/opendkim/opendkim.conf || true
fi


# Start Postfix in foreground
exec postfix start-fg
