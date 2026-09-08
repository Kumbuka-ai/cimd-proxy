# Security policy

`cimd-proxy` sits on an authentication path. A defect here is not a bug report,
it is a disclosure, so please treat it as one.

## Reporting a vulnerability

Report privately through GitHub's **Report a vulnerability** button under the
repository's Security tab, which opens a private advisory visible only to the
maintainers.

Please do not open a public issue, and please do not post a proof of concept
publicly before a fix is available.

A report is more useful with: the version or commit, the configuration shape
that reproduces it (with your own secrets removed), what you expected, and what
happened instead.

## What is in scope

The boundary this project claims to hold:

- the client identity path — metadata document fetching, the host allowlist,
  document validation, dynamic registration
- SSRF and DNS-rebinding protection on that fetch
- PKCE enforcement and the authorization code path
- the envelope that carries the upstream refresh token
- resource binding — that a token is requested for the resource the client
  actually asked for

A finding that lets a caller escape any of those is in scope, as is one that
makes the proxy read, log or leak a token.

## What is out of scope

- weaknesses of the upstream identity provider itself
- a deployment that configures `CIMD_ALLOWED_DOMAINS=*` and is then reached by
  an unexpected client; that value permits any host by definition
- missing TLS in front of the proxy — terminate TLS at your reverse proxy
- rate limiting and abuse control, which belong to the layer in front

## Supported versions

The latest released tag is the supported one. There is no long-term support
branch.
