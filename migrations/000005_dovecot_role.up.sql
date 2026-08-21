-- Create read-only role for Dovecot authentication and userdb lookups
DO
$do$
BEGIN
   IF NOT EXISTS (
      SELECT FROM pg_catalog.pg_roles
      WHERE rolname = 'mailopen_dovecot') THEN

      CREATE ROLE mailopen_dovecot WITH LOGIN PASSWORD 'dovecot_secret';
   END IF;
   EXECUTE format('GRANT CONNECT ON DATABASE %I TO mailopen_dovecot', current_database());
END
$do$;

GRANT USAGE ON SCHEMA public TO mailopen_dovecot;
GRANT SELECT (id, email, password_hash, status, provisioning_status, domain_id) ON mailboxes TO mailopen_dovecot;
GRANT SELECT (id, name, status) ON domains TO mailopen_dovecot;
