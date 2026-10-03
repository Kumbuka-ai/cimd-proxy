# Measurement: Keycloak JWT Authorization Grant for personal access tokens

The personal-access-token exchange rests on Keycloak's JWT Authorization Grant
(RFC 7523, `urn:ietf:params:oauth:grant-type:jwt-bearer`). Before it was built,
the grant was measured against a local Keycloak of the version this proxy is
deployed with, so that every property the exchange relies on is observed, not
read from documentation.

- `realm.json` — throwaway realm. Every secret in it is a fixed test value for
  a local container; it is not an export of any real realm.
- `probe.py` — sets up the realm, serves a JWKS for the "proxy" key and runs
  every probe twice; the run fails if the two outcomes differ.
- `results.txt` — the output of the run the implementation was based on.

## Run

```bash
docker run -d --name kc-jag -p 18080:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  --add-host host.docker.internal:host-gateway \
  quay.io/keycloak/keycloak:26.7.4 start-dev --features=cimd
python measurements/jwt-authorization-grant/probe.py
```

`--features=cimd` is the feature set of the production image; the grant needs
no further flag.

## What was observed (Keycloak 26.7.4)

| # | Question | Observed |
|---|---|---|
| 1 | Feature flag? | `JWT_AUTHORIZATION_GRANT`, type `DEFAULT`, enabled without a flag (`/admin/serverinfo`). The startup log names only `cimd:v1` as experimental. |
| 2 | Proxy-signed assertion via JWKS URL | `200`, `azp` = the resource's upstream client, `aud` = the resource |
| 3 | Matching the user | Only through a federated identity link at the identity provider (`sub` = the link's `userId`). Unlinked user, or `sub` = username: `invalid_grant "User not found"`. Creating a link needs `realm-management/manage-users`; `view-users` gets `403`. |
| 4 | Roles per request | With `fullScopeAllowed=false` the roles are those of the requested optional client scopes: `set-memory` gives `[r-memory]`, `set-dispatch` gives `[dispatch-executor]`. A scope whose roles the user does not hold is dropped from `scope` and adds no role. |
| 5 | Refusals | Disabled user: `User is not enabled`. Foreign key, also with a spoofed `kid`: `Invalid signature`. Expired: `Token is not active`. Replayed `jti`: `Token reuse detected`. Unknown issuer: `No Identity Provider for provided issuer`. |
| 6 | Lifetime, refresh | `access.token.lifespan` on the client sets `exp - iat` (60 and 300 measured). No refresh token, also not with `offline_access`. |
| 7 | Key rotation | A new `kid` is fetched only if the last JWKS fetch is at least ~10 s old; a removed key stays accepted until the next fetch. `POST /admin/realms/{realm}/clear-keys-cache` ends that at once. |
| 8 | Tenants as organizations | The `organization` claim names the owner's own membership. `scope=organization:<alias>` narrows a multi-member owner to exactly that one; for a non-member it yields no claim. A client without the `organization` scope refuses `organization:<alias>` with `invalid_scope`. Tokens from this grant carry no `sid`. |

Two settings matter beyond the defaults:

- `jwtAuthorizationGrantAllowedClockSkew` defaults to `0`. With it, an assertion
  whose `iat` is a fraction of a second ahead of Keycloak's clock is refused as
  `Token was issued in the future` (seen in the first run). The realm here uses 5.
- `jwtAuthorizationGrantMaxAllowedAssertionExpiration` bounds the age of `iat`,
  not `exp - iat`: an assertion with `exp = now + 3600` and a fresh `iat` is
  accepted. The proxy therefore bounds its own assertion lifetime (60 s).
