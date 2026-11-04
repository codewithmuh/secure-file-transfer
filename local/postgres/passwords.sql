-- Local stack only: gives every login role that sft.data.bootstrap made the same obviously fake
-- password (docs/local-development.md 3). In AWS the roles have no password; they sign in with IAM
-- tokens (encryption and keys 6.3). The value is the test suite's (services/api/tests/pg.py), because
-- roles belong to the whole server and `make test` against this stack sets that one: one value
-- means a test run never locks the API out. Run by the db-passwords service on every `make up`.
DO $$
DECLARE
    role_name name;
BEGIN
    FOR role_name IN
        SELECT rolname FROM pg_roles
        WHERE rolname LIKE 'sft\_%' AND rolcanlogin AND NOT rolsuper
        ORDER BY rolname
    LOOP
        EXECUTE format('ALTER ROLE %I PASSWORD %L', role_name, 'test-only-password');
    END LOOP;
END
$$;
