# Deploying cimd-proxy

The reference shape for a compose-based deployment behind an existing reverse
proxy. Nothing here is required — the container takes its whole configuration
from the environment and does not care how it was started.

Three files:

| File | Role |
|---|---|
| `.env.example` | Annotated environment template. Copy to `deploy.env` and fill in. |
| `compose.fragment.yml` | The service definition. Merge into your stack; do not run it alone. |
| `caddy/example.caddy` | Two site blocks: the proxy's own, and a protected resource publishing its metadata. |

## What has to exist first

**One upstream client per protected resource.** In your identity provider,
each resource gets a client the proxy authenticates as. That client needs an
audience mapper producing a token the resource server accepts — the proxy
relays the upstream token untouched, so whatever the upstream mints is what the
resource sees.

**A redirect URI on that client** pointing at the proxy's `/callback`.

**A network the reverse proxy shares with the container.** The fragment joins
an external network named `edge`; rename it to whatever yours is called.

## Bringing it up

```bash
cp deploy/.env.example deploy.env
# fill in: public URL, a fresh secret key, the resource table
docker compose --env-file deploy.env up -d cimd-proxy
curl -s https://auth.example.com/.well-known/oauth-authorization-server
```

The discovery document is the first thing to check: it is what a client reads,
and it is served from the running configuration rather than from the file, so a
value that did not arrive shows up here.

## Verifying a connection

Work outward, one layer at a time, and stop at the first surprise.

1. **The resource metadata** — fetch it at both well-known locations and
   confirm the `resource` value equals the URL a client addresses, path
   included.
2. **The discovery document** — confirm the issuer matches `PROXY_PUBLIC_URL`
   and that `registration_endpoint` is present if you expect clients to
   register dynamically.
3. **The authorization step** — connect a real client. A refusal here is typed
   and names its reason in the proxy log; the common ones are a `resource`
   value absent from the table and a `redirect_uri` that violates the
   RFC 8252 §7.3 shape (http on a non-loopback host, or the `localhost` name
   rather than the `127.0.0.1` / `[::1]` literal).
4. **The token step** — a successful connection is not proof that the audience
   is right. Call the resource once; a token with the wrong audience is
   rejected there, not at the proxy.

A client that lists tools has completed steps 1 to 3. Only step 4 shows the
chain actually carries.

## Personal access tokens (optional)

Off unless `PAT_DATABASE_URL` is set. Everything below was measured against
Keycloak 26.7.4 (`measurements/jwt-authorization-grant/`); another provider
needs the equivalent of each item.

### In the identity provider

1. **An identity provider of type "JWT Authorization Grant"** (alias as in
   `PAT_IDP_ALIAS`): issuer = `PAT_ASSERTION_ISSUER` (default
   `PROXY_PUBLIC_URL`), *Use JWKS URL* on, JWKS URL =
   `<PROXY_PUBLIC_URL>/pat/jwks.json`, *JWT Authorization Grant* on, assertion
   signature algorithm `RS256`, allowed clock skew a few seconds (with the
   default `0`, an assertion issued a fraction of a second ahead of the
   provider's clock is refused). The provider must reach the JWKS URL.
2. **A confidential client per resource** (`RESOURCE_n_PAT_CLIENT_ID`):
   capability *JWT Authorization Grant* on, this identity provider in its
   allowed list, *Full scope allowed* off, the audience mapper(s) the resource
   expects, and the access-token lifespan the short token should have (5 minutes
   is the intended default; the proxy sets nothing on top). The grant refuses
   public clients, so a resource whose interactive client is public needs this
   second client.
3. **A client scope per permission set**, with role scope mappings for the
   roles the set carries, attached to the client in step 2 as *optional*. List
   them in `PAT_SCOPES`. The roles of an issued token are exactly those of the
   requested scopes; a scope whose roles the owner does not hold is withheld.
4. **Organizations:** attach the `organization` client scope to the client in
   step 2 as optional. Every token is bound to one organization of its owner
   and requests `organization:<alias>`; without the scope on the client the
   exchange fails with `invalid_scope` rather than issuing an unbound token. An
   owner who belongs to no organization gets no token
   (`403 organization_required`), and a stored token without one is never
   exchanged.
5. **An admin client** (`PAT_ADMIN_CLIENT_ID`): confidential, service account
   with `realm-management` → `manage-users` (needed to link an owner to the
   identity provider; `view-users` is not enough), and the client attribute
   `allow.token.introspection.without.audience.check=true` (an owner's token is
   audienced for its resource, and the provider otherwise answers the proxy's
   introspection with `active: false`).

### In the database

Two roles. The **migrator** runs the migrations and owns the schema; it needs
`CREATEROLE` and `CREATE` on the database and nothing more — never a superuser
and never `BYPASSRLS` (the migration refuses either, `CP001`). The **runtime
role** is the one the proxy connects as; the first migration creates it with a
placeholder password, and it must not carry `SUPERUSER` or `BYPASSRLS` either
(refused, `CP002`). Once, as a superuser:

```sql
CREATE ROLE cimd_proxy_migrator LOGIN CREATEROLE PASSWORD '…';
GRANT CONNECT, CREATE ON DATABASE app TO cimd_proxy_migrator;
```

The migrations run from `ghcr.io/kumbuka-ai/cimd-proxy-migrations:<tag>`, the
same tag as the proxy, before the first start and after every upgrade. It reads
Flyway's own variables:

| Variable | Meaning | Default |
|---|---|---|
| `FLYWAY_URL` | `jdbc:postgresql://<host>:5432/<database>` | — |
| `FLYWAY_USER`, `FLYWAY_PASSWORD` | the migrator | — |
| `FLYWAY_SCHEMAS` | the schema (= `PAT_DATABASE_SCHEMA`) | `cimd_proxy` |
| `FLYWAY_PLACEHOLDERS_APP_ROLE` | the runtime role (the user of `PAT_DATABASE_URL`) | `cimd_proxy` |

With `FLYWAY_USER` and `FLYWAY_PASSWORD` both empty the image does nothing and
exits 0 — personal access tokens are off — so a deployment can run it
unconditionally before the proxy (`depends_on` with
`condition: service_completed_successfully`, see `compose.fragment.yml`). One of
the two without the other is a configuration error and exits 2.

After the first run, rotate the runtime role's placeholder password and put the
new one into `PAT_DATABASE_URL`:

```sql
ALTER ROLE cimd_proxy PASSWORD '…';
```

The migrations grant the runtime role `SELECT` and `INSERT` on the token table,
`UPDATE` on two columns (`last_used_at`, `revoked_at`) and `SELECT` on the
Flyway history; no delete, no DDL. The proxy refuses to start while the
history is behind the code.

### Smoke test

`deploy/pat-smoke.sh` runs a token end to end against a live deployment:
create one for a permission set, exchange it, call one MCP tool the set
permits and one it does not (which must be refused with a reason you name),
revoke it, and see the exchange refused. It needs an owner's access token from
an interactive sign-in that carries `sid` and `organization`, revokes the token
it created on every exit, and prints no credential. The variables are listed at
its head.

### Rotating the signing key

1. Add the new key as the next `PAT_SIGNING_KEY_n_*` entry and restart. Both
   keys are now published; the old one still signs.
2. Set `PAT_SIGNING_KID` to the new key and restart. The provider fetches an
   unknown key id only when its last fetch is about ten seconds old, so the
   first exchanges after the switch can be refused for that long.
3. Remove the old key and restart, then **clear the provider's key cache**
   (Keycloak: *Realm settings → Keys → Clear keys cache*, or
   `POST /admin/realms/<realm>/clear-keys-cache`). The provider keeps accepting
   a key it has cached until it reloads; the clear is what ends the old key.

## Rollback before forward

Pin the image to a tag, never `latest`, and note the tag currently running
before changing it. Without personal access tokens the proxy holds no state
beyond its configuration, so a rollback is a tag change and a restart — with
one exception: changing `PROXY_SECRET_KEY` invalidates every refresh token
already issued, and every connected client has to authorize again. Treat that
value as permanent for the life of a deployment.

With personal access tokens the database is state. Migrations only add, and
the proxy refuses to start only against a schema *older* than itself, so an
image rollback runs against the newer schema without a database rollback.

## Operating notes

- The container runs as a non-root user and exposes a `/healthz` liveness
  probe.
- Logs are JSON on stdout. User-controlled fields are neutralised before they
  are written; log injection through a crafted client identifier is a defect,
  not a curiosity.
- `CIMD_DEBUG=true` adds detail about metadata document handling. It is a
  diagnostic setting, not a production one.
- Rate limiting and abuse control belong to the layer in front. The proxy does
  not implement them and does not pretend to.
