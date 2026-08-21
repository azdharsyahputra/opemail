#!/bin/bash
set -e

# If config volume mounted at /config, copy config files into /etc/dovecot
if [ -d "/config" ]; then
    mkdir -p /etc/dovecot/conf.d /etc/dovecot/sql
    cp -a /config/* /etc/dovecot/ 2>/dev/null || true
    chown -R root:dovecot /etc/dovecot 2>/dev/null || true
    chmod 0640 /etc/dovecot/sql/*.conf.ext 2>/dev/null || true
fi

# Ensure /var/vmail exists and has correct ownership (vmail:vmail 5000:5000 0750)
mkdir -p /var/vmail
chown -R vmail:vmail /var/vmail
chmod 0750 /var/vmail

# Start Dovecot in foreground
exec dovecot -F
