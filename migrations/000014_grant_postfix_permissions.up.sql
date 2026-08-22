DO $$
BEGIN
   IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'mailopen_postfix') THEN
      CREATE ROLE mailopen_postfix WITH LOGIN PASSWORD 'postfix_secret';
   END IF;
   IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'mailopen_dovecot') THEN
      CREATE ROLE mailopen_dovecot WITH LOGIN PASSWORD 'dovecot_secret';
   END IF;
END $$;

GRANT USAGE ON SCHEMA public TO mailopen_postfix, mailopen_dovecot;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO mailopen_postfix, mailopen_dovecot;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO mailopen_postfix, mailopen_dovecot;
