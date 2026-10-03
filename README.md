# cimd-proxy

![License](https://img.shields.io/badge/license-Apache_2.0-FF5B1F?style=flat-square)
![Python](https://img.shields.io/badge/Python-3.13-2D4059?style=flat-square&logo=python&logoColor=F4F1EA)
![FastAPI](https://img.shields.io/badge/FastAPI-2D4059?style=flat-square&logo=fastapi&logoColor=F4F1EA)
![OAuth](https://img.shields.io/badge/OAuth-2.1-2D4059?style=flat-square)
![CIMD](https://img.shields.io/badge/CIMD-draft--02-FF5B1F?style=flat-square)
![MCP](https://img.shields.io/badge/MCP-Streamable_HTTP-FF5B1F?style=flat-square)
![Interactive tokens relayed unread](https://img.shields.io/badge/interactive_tokens-relayed_unread-141820?style=flat-square&labelColor=FF5B1F)
![Personal access tokens stored as hashes](https://img.shields.io/badge/access_tokens-hash_only-141820?style=flat-square&labelColor=FF5B1F)
[![Quality gate status](https://sonarcloud.io/api/project_badges/measure?project=Kumbuka-ai_cimd-proxy&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=Kumbuka-ai_cimd-proxy)

An OAuth 2.1 authorization server that speaks **Client ID Metadata Documents**
outward and federates to an existing OIDC provider inward, so MCP clients
connect by URL alone. On the interactive path it relays the provider's tokens
without reading them. Optionally it also issues personal access tokens that an
agent exchanges for a short-lived token from the same provider.

## The problem

MCP clients cannot register with your authorization server. Hosted assistants
expect to hand over a URL and be admitted; a classic OIDC provider expects a
client that was registered beforehand, with an identifier somebody typed in.
The gap between those two positions is where connections fail.

There is a second gap behind the first. An upstream that does not honour the
RFC 8707 `resource` parameter cannot mint a correctly audienced token for a
client it has just met, so even a successful login yields a token the resource
server rejects.

## What this does

`cimd-proxy` presents an OAuth 2.1 authorization server to the client, accepts
a Client ID Metadata Document — or a dynamic registration — as the client's
identity, and federates the actual authentication to an OIDC provider you
already run. Each protected resource is mapped onto a pre-configured upstream
client whose audience mapper is already set, and the upstream token response is
relayed through unchanged.

Your provider needs one confidential client per protected resource and no
further changes. No fork, no extension, no custom authenticator.

## What the proxy reads, stores and signs

**On the interactive path the proxy does not read the token.** It does not
issue, verify, parse or sign the tokens of an authorization-code sign-in. The
upstream token response is relayed verbatim, with a single exception: the
`refresh_token` field is replaced by a sealed envelope carrying the upstream
refresh token together with the resource identifier, so a refresh can be
routed without any server-side session state. This is unchanged whether or not
personal access tokens are switched on.

**Personal access tokens are a second path, off unless configured**, and on
that path the proxy does more, all of it named here:

- It **issues** the personal access token itself — `kmb_pat_`, 256 bits of
  randomness, a checksum — and hands it out exactly once.
- It **stores**, in PostgreSQL, the SHA-256 of that token with its owner,
  tenant, resources, permission set, expiry, last use and revocation. Never the
  token.
- It **verifies** the owner's own access token at the management endpoints, by
  asking the provider (token introspection) rather than by parsing it.
- It **signs** one thing: a 60-second assertion for the JWT Authorization Grant
  (RFC 7523), verified by the provider against the proxy's published keys. The
  access token an agent receives is issued by the provider, never by the proxy.
- It **reads** the provider's token response on this path in two places: it
  drops a `refresh_token`, and when a personal access token is created it reads
  the granted `scope` of a trial exchange. It does not parse the access token.

What it enforces on the interactive path is the boundary:

- metadata documents are fetched only from allowlisted hosts
- SSRF and DNS-rebinding protection — every resolved address is filtered
  against private, loopback, link-local, reserved, multicast and unspecified
  ranges, and the socket is pinned to the exact address that was validated,
  with the hostname carried only in `Host` and TLS SNI
- no development-mode loopback exception exists
- PKCE S256 is required
- the document body is capped incrementally, redirects are refused
- RFC 8707 `resource` binding, with scheme-based normalisation of the root
  path only — nothing else is folded

## Endpoints

| Path | Method | Purpose |
|---|---|---|
| `/.well-known/oauth-authorization-server` | GET | RFC 8414 discovery document |
| `/.well-known/openid-configuration` | GET | Alias for the discovery document |
| `/authorize` | GET | Authorization endpoint; validates the client identity |
| `/callback` | GET | Upstream redirect target, echoes `iss` per RFC 9207 |
| `/token` | POST | Authorization code and refresh grants; token exchange for personal access tokens when configured |
| `/register` | POST | RFC 7591 dynamic client registration |
| `/healthz` | GET | Liveness probe |
| `/pat/tokens` | POST, GET | Create a personal access token, list your own (configured only) |
| `/pat/tokens/{id}` | DELETE | Revoke one of your own (configured only) |
| `/pat/jwks.json` | GET | Public keys the provider verifies assertions with (configured only) |

A client identifies itself in one of two ways at `/authorize`. An `https` URL
is read as a Client ID Metadata Document and fetched under the rules above; a
registration envelope from `/register` is read as a dynamic registration.
Anything else is a typed refusal.

## Standards

- `draft-ietf-oauth-client-id-metadata-document-02` — CIMD
- RFC 8414 — authorization server metadata
- RFC 9728 — protected resource metadata
- RFC 8707 — resource indicators
- RFC 7591 — dynamic client registration
- RFC 9207 — `iss` in the authorization response
- RFC 7636 — PKCE, S256 only
- RFC 8693 — token exchange, for personal access tokens
- RFC 7523 — JWT Authorization Grant, towards the provider
- RFC 7662 — token introspection, for the owner at the management endpoints

## Personal access tokens

A person creates a long-lived token for an agent and gives it a permission set
— a list of the provider's client scopes, each of which carries roles. The
agent sends the token to `/token` and gets back an ordinary short-lived access
token from the provider that carries only the roles of that set. When it runs
out, the agent exchanges again. There is no refresh token on this path.

```bash
# The owner, with an access token from an interactive sign-in:
curl -s -X POST https://auth.example.com/pat/tokens \
  -H "Authorization: Bearer $OWNER_ACCESS_TOKEN" -H 'Content-Type: application/json' \
  -d '{"name": "nightly-agent", "resources": ["https://mcp.example.com/mcp"],
       "scopes": ["agent-read"], "expires_in_days": 30}'
# -> {"token": "kmb_pat_…", "id": "…", "expires_at": "…", …}   (shown once)

# The agent, whenever it needs a token:
curl -s https://auth.example.com/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
  -d subject_token="$PAT"
# -> {"access_token": "…", "expires_in": 300, "issued_token_type": "…access_token"}
```

The rules:

- Expiry is mandatory: 90 days by default, anything above 365 days only with
  `"allow_long_lifetime": true`.
- A permission set may contain only scopes listed in `PAT_SCOPES`, and only
  scopes the owner may carry: at creation the proxy performs a trial exchange
  and refuses the token if the provider withholds any requested scope.
- A token of an owner in one organization is bound to it; the exchange
  requests exactly that organization, so it never comes back naming another.
- Management needs a token from an interactive sign-in. A token obtained from
  a personal access token carries no session and is refused, so a leaked
  personal access token cannot mint more.
- A user sees and revokes only their own tokens. A revoked or expired token,
  or one with a wrong checksum, is refused — the last without a database
  lookup.

What the provider has to provide — an identity provider of type JWT
Authorization Grant, a confidential client per resource, client scopes per
permission set — and how keys are rotated is in `deploy/README.md`.

## Quick start

```bash
cp deploy/.env.example deploy.env
# edit deploy.env — public URL, a fresh secret key, your upstream, your resources
docker run --rm --env-file deploy.env -p 8080:8080 ghcr.io/kumbuka-ai/cimd-proxy:v0.2.1
curl -s http://127.0.0.1:8080/.well-known/oauth-authorization-server
```

Every required value is checked at start. A missing one is a loud startup
error, never a default that quietly does something else.

Personal access tokens are off by default. To switch them on, provision the
database and run `python -m cimd_proxy migrate` with a schema-owning role
(`PAT_MIGRATION_DATABASE_URL`) before the first start; the proxy refuses to
start while its schema is behind the code.

`deploy/` carries the reference shape for a compose-based deployment behind an
existing reverse proxy: a compose fragment, an annotated environment template,
and a Caddy example covering both the proxy's own site and the protected
resource metadata a resource server has to publish.

## Configuration

All configuration is environment variables; see `deploy/.env.example` for the
annotated list. The resource table is indexed rather than embedded JSON,
because these values are written into an env file and read through
`docker compose --env-file`, where embedded JSON does not quote reliably.
Indices are read contiguously from zero; a set index above a gap is a loud
startup error rather than a silently shortened table.

## Development

```bash
python -m pip install -e ".[test,dev]"
python -m ruff check src tests
python -m pytest --cov=src/cimd_proxy
```

The tests under `tests/integration` start PostgreSQL and Keycloak containers
and need Docker; without it they are skipped with the reason printed, unless
`CIMD_PROXY_REQUIRE_INTEGRATION=1` is set, as in CI, where a missing Docker
fails the run. `measurements/` holds the probes the personal-access-token path
was built on and the observed red runs of its gates.

The test suite ships **red probes in pairs**: a guarded run that must reject
and a bypassed control run that must admit, plus a strict-xfail control that
captures the observed red state of each gate. A gate that has never been seen
failing is not a gate, and a suite that only ever proves the happy path proves
nothing about the boundary.

## Versioning

Tags carry a `v` prefix (`v0.1.0`, `v0.2.1`, …) and images are published to
`ghcr.io/kumbuka-ai/cimd-proxy` on tag push.

## Licence

Apache-2.0 — see `LICENSE` and `NOTICE`.

---

## Who builds this

`cimd-proxy` came out of [Kumbuka](https://kumbuka.ai), a governed memory and
control layer for AI assistants that is reached over MCP. Kumbuka needed its
own MCP services to be connectable from hosted assistants without handing
anybody a client secret, the gap above was in the way, and the proxy is what
closed it. It is released on its own because the gap is not ours alone.

If you run MCP servers behind an identity provider, the same problem is
probably sitting in your backlog.
