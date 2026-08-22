#!/bin/bash
set -e

# If config volume mounted at /config, copy config files into /etc/dovecot
if [ -d "/config" ] && [ -f "/config/dovecot.conf" ]; then
    mkdir -p /etc/dovecot/conf.d /etc/dovecot/sql
    cp -a /config/* /etc/dovecot/ 2>/dev/null || true
    chown -R root:dovecot /etc/dovecot 2>/dev/null || true
    chmod 0640 /etc/dovecot/sql/*.conf.ext 2>/dev/null || true
fi

# Auto-generate fallback TLS certificate if referenced by 10-ssl.conf and missing
if [ -f "/etc/dovecot/conf.d/10-ssl.conf" ]; then
    CERT_PATH=$(grep -E '^\s*ssl_cert\s*=' /etc/dovecot/conf.d/10-ssl.conf | sed -E 's/.*<//' | tr -d ' ')
    KEY_PATH=$(grep -E '^\s*ssl_key\s*=' /etc/dovecot/conf.d/10-ssl.conf | sed -E 's/.*<//' | tr -d ' ')

    if [ -n "$CERT_PATH" ] && [ ! -f "$CERT_PATH" ]; then
        mkdir -p "$(dirname "$CERT_PATH")" "$(dirname "$KEY_PATH")" 2>/dev/null || true
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout "$KEY_PATH" \
            -out "$CERT_PATH" \
            -subj "/CN=mailopen" 2>/dev/null || true
        chmod 0640 "$KEY_PATH" "$CERT_PATH" 2>/dev/null || true
    fi
fi

# Ensure default system fallback cert exists
mkdir -p /etc/ssl/dovecot
if [ ! -f "/etc/ssl/dovecot/server.pem" ]; then
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/ssl/dovecot/server.key \
        -out /etc/ssl/dovecot/server.pem \
        -subj "/CN=localhost" 2>/dev/null || true
fi

# Ensure /var/vmail exists and has correct ownership (vmail:vmail 5000:5000 0750)
mkdir -p /var/vmail
chown -R vmail:vmail /var/vmail 2>/dev/null || true
chmod 0750 /var/vmail 2>/dev/null || true

# Ensure /var/spool/postfix/private exists for Postfix SASL socket
mkdir -p /var/spool/postfix/private
chown -R postfix:postfix /var/spool/postfix/private 2>/dev/null || true
chmod 0750 /var/spool/postfix/private 2>/dev/null || true

# Start Dovecot in foreground
exec dovecot -F
