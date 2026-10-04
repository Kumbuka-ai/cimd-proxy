-- Personal access tokens: the schema, the runtime role and its grants.
--
-- Applied by Flyway (the cimd-proxy-migrations image). ${flyway:defaultSchema}
-- is the schema Flyway was pointed at (FLYWAY_SCHEMAS) and creates before this
-- file runs; ${app_role} is the role the proxy connects as
-- (FLYWAY_PLACEHOLDERS_APP_ROLE). Both are checked to be plain lower-case
-- identifiers by the image's entrypoint before Flyway starts, because Flyway
-- substitutes them as text.
--
-- TWO ROLES. The migrator runs this file and owns everything it creates. It
-- needs CREATEROLE (the block below creates the runtime role) and CREATE on the
-- database (Flyway creates the schema), and nothing beyond that. The runtime
-- role owns nothing and holds exactly the grants at the end of this file.

-- ---------------------------------------------------------------------------
-- 1. The migrator carries no policy exemption, and neither does the runtime
--    role.
--
-- A superuser or BYPASSRLS role is exempt from every row-level-security policy
-- this schema could ever gain, silently: rows returned, nothing raised. Neither
-- attribute can be granted or taken away by a CREATEROLE migrator, so this
-- block refuses rather than repairs -- a migration that could quietly remove an
-- attribute could quietly add one. Role lifecycle belongs to the operator.
--
-- The runtime role is created here when it does not exist, with a placeholder
-- password, so a cold start needs no manual step before the first migration.
-- The placeholder is not a credential: a deployment rotates it with
-- `ALTER ROLE <app_role> PASSWORD '...'` from its own secret store before the
-- proxy is switched to personal access tokens. A role created here cannot carry
-- SUPERUSER or BYPASSRLS; the check is for a role an operator created
-- beforehand.
--
-- The checks run when this migration is applied. They are not a standing
-- guard: an attribute acquired later is not caught here.
--
-- ERRCODEs CP001 and CP002 are application-defined; no standard class means
-- "this role holds too much". The probes match on the code, not the text.
-- ---------------------------------------------------------------------------
DO $do$
DECLARE
    app_role   text := '${app_role}';
    is_super   boolean;
    is_bypass  boolean;
BEGIN
    SELECT rolsuper, rolbypassrls INTO is_super, is_bypass
    FROM pg_catalog.pg_roles WHERE rolname = current_user;

    IF is_super OR is_bypass THEN
        RAISE EXCEPTION
            'the migrating role % carries superuser=% bypassrls=% and this schema will '
            'not be created under it. Migrate as a role that carries neither; CREATEROLE '
            'and CREATE on the database are all this migration needs.',
            current_user, is_super::text, is_bypass::text
            USING ERRCODE = 'CP001';
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = app_role) THEN
        EXECUTE format('CREATE ROLE %I LOGIN PASSWORD %L', app_role, 'change-me-cimd-proxy');
        RAISE NOTICE 'created role % with the placeholder password -- rotate it', app_role;
    END IF;

    SELECT rolsuper, rolbypassrls INTO is_super, is_bypass
    FROM pg_catalog.pg_roles WHERE rolname = app_role;

    IF is_super OR is_bypass THEN
        RAISE EXCEPTION
            'the runtime role % carries superuser=% bypassrls=%. Either one exempts it '
            'from every policy this schema may carry, and this migration will not grant '
            'it anything. Recreate the role without them.',
            app_role, is_super::text, is_bypass::text
            USING ERRCODE = 'CP002';
    END IF;
END
$do$;

-- ---------------------------------------------------------------------------
-- 2. The token table.
--
-- A row holds the SHA-256 of a token, never the token. tenant is the
-- organization alias the token is bound to and is never empty: a token without
-- an organization is refused when it is created and when it is exchanged, and
-- the CHECK keeps a row of that shape from existing at all.
-- ---------------------------------------------------------------------------
CREATE TABLE ${flyway:defaultSchema}.personal_access_token (
    id            uuid        PRIMARY KEY,
    tenant        text        NOT NULL CHECK (tenant <> ''),
    realm_issuer  text        NOT NULL,
    owner_sub     text        NOT NULL,
    name          text        NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    token_hash    bytea       NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    resources     text[]      NOT NULL CHECK (cardinality(resources) >= 1),
    scopes        text[]      NOT NULL,
    created_at    timestamptz NOT NULL,
    expires_at    timestamptz NOT NULL,
    last_used_at  timestamptz,
    revoked_at    timestamptz,
    CHECK (expires_at > created_at)
);

COMMENT ON COLUMN ${flyway:defaultSchema}.personal_access_token.tenant IS
    'Organization alias the token is bound to; never empty.';

CREATE INDEX personal_access_token_owner
    ON ${flyway:defaultSchema}.personal_access_token (realm_issuer, owner_sub);

-- ---------------------------------------------------------------------------
-- 3. The entitlement, written out.
--
-- The runtime role may read and insert tokens and may change exactly two
-- columns: last_used_at on every exchange and revoked_at on revocation. It
-- cannot rewrite an owner, a hash, a set or an expiry, and it cannot delete: a
-- revoked token stays as a row, so revocation is a fact, not an absence. No
-- CREATE on the schema: a role that can create a table owns it.
--
-- SELECT on the Flyway history is the one read outside the token table: the
-- proxy refuses to start while the schema is behind its code, and this is how
-- it knows. It cannot write the history.
-- ---------------------------------------------------------------------------
REVOKE ALL ON SCHEMA ${flyway:defaultSchema} FROM PUBLIC;
GRANT USAGE ON SCHEMA ${flyway:defaultSchema} TO "${app_role}";
GRANT SELECT, INSERT ON ${flyway:defaultSchema}.personal_access_token TO "${app_role}";
GRANT UPDATE (last_used_at, revoked_at)
    ON ${flyway:defaultSchema}.personal_access_token TO "${app_role}";
GRANT SELECT ON ${flyway:defaultSchema}.flyway_schema_history TO "${app_role}";
