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
chown -R vmail:vmail /var/vmail
chmod 0750 /var/vmail

# Fix postfix permissions & generate aliases db if needed
postfix set-permissions 2>/dev/null || true
newaliases 2>/dev/null || true

# Start Postfix in foreground
exec postfix start-fg
