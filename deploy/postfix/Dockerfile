FROM alpine:3.19

RUN apk add --no-cache postfix postfix-pgsql opendkim opendkim-utils bash perl ca-certificates

# Ensure vmail user has UID/GID 5000
RUN deluser vmail 2>/dev/null || true; \
    delgroup vmail 2>/dev/null || true; \
    addgroup -g 5000 vmail && \
    adduser -u 5000 -G vmail -D -h /var/vmail -s /sbin/nologin vmail

RUN mkdir -p /var/vmail && chown -R vmail:vmail /var/vmail && chmod 0750 /var/vmail

COPY deploy/postfix/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 25 587

ENTRYPOINT ["/entrypoint.sh"]
