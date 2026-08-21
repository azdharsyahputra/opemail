DO
$do$
BEGIN
   IF EXISTS (
      SELECT FROM pg_catalog.pg_roles
      WHERE rolname = 'mailopen_dovecot') THEN

      EXECUTE format('REVOKE CONNECT ON DATABASE %I FROM mailopen_dovecot', current_database());
   END IF;
END
$do$;

REVOKE ALL PRIVILEGES ON TABLE mailboxes FROM mailopen_dovecot;
REVOKE ALL PRIVILEGES ON TABLE domains FROM mailopen_dovecot;
REVOKE ALL PRIVILEGES ON SCHEMA public FROM mailopen_dovecot;
DROP ROLE IF EXISTS mailopen_dovecot;
