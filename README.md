# cimd-proxy

![License](https://img.shields.io/badge/license-Apache_2.0-FF5B1F?style=flat-square)
![Python](https://img.shields.io/badge/Python-3.13-2D4059?style=flat-square&logo=python&logoColor=F4F1EA)
![FastAPI](https://img.shields.io/badge/FastAPI-2D4059?style=flat-square&logo=fastapi&logoColor=F4F1EA)
![OAuth](https://img.shields.io/badge/OAuth-2.1-2D4059?style=flat-square)
![CIMD](https://img.shields.io/badge/CIMD-draft--02-FF5B1F?style=flat-square)
![MCP](https://img.shields.io/badge/MCP-Streamable_HTTP-FF5B1F?style=flat-square)
![Never reads your token](https://img.shields.io/badge/your_token-never_read-141820?style=flat-square&labelColor=FF5B1F)
[![Quality gate status](https://sonarcloud.io/api/project_badges/measure?project=Kumbuka-ai_cimd-proxy&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=Kumbuka-ai_cimd-proxy)

An OAuth 2.1 authorization server that speaks **Client ID Metadata Documents**
outward and federates to an existing OIDC provider inward, so MCP clients
connect by URL alone. It never issues, verifies, parses or signs a token.

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

## The load-bearing rule

**The proxy never reads the token.** It does not issue one, does not verify
one, does not parse one and does not sign one. The upstream token response is
relayed verbatim, with a single exception: the `refresh_token` field is
replaced by a sealed envelope carrying the upstream refresh token together with
the resource identifier, so a refresh can be routed without any server-side
session state.

What it does enforce is the boundary:

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
| `/token` | POST | Authorization code and refresh grants |
| `/register` | POST | RFC 7591 dynamic client registration |
| `/healthz` | GET | Liveness probe |

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

## Quick start

```bash
cp deploy/.env.example deploy.env
# edit deploy.env — public URL, a fresh secret key, your upstream, your resources
docker run --rm --env-file deploy.env -p 8080:8080 ghcr.io/kumbuka-ai/cimd-proxy:v0.2.1
curl -s http://127.0.0.1:8080/.well-known/oauth-authorization-server
```

Every required value is checked at start. A missing one is a loud startup
error, never a default that quietly does something else.

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
