-- Personal access tokens. {schema} and {app_role} are filled in by the
-- migration runner as quoted identifiers.
--
-- The runtime role may read and insert tokens and may change exactly two
-- columns: last_used_at on every exchange and revoked_at on revocation. It
-- cannot rewrite an owner, a hash, a set or an expiry, and it cannot delete:
-- a revoked token stays as a row, so revocation is a fact, not an absence.

CREATE TABLE {schema}.personal_access_token (
    id            uuid        PRIMARY KEY,
    tenant        text        NOT NULL,
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

COMMENT ON COLUMN {schema}.personal_access_token.tenant IS
    'Organization alias the token is bound to; empty when the owner belongs to none.';

CREATE INDEX personal_access_token_owner
    ON {schema}.personal_access_token (realm_issuer, owner_sub);

GRANT USAGE ON SCHEMA {schema} TO {app_role};
GRANT SELECT, INSERT ON {schema}.personal_access_token TO {app_role};
GRANT UPDATE (last_used_at, revoked_at) ON {schema}.personal_access_token TO {app_role};
GRANT SELECT ON {schema}.schema_history TO {app_role};
