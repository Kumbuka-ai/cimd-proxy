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
# fill in: public URL, a fresh secret key, the allowlist, the resource table
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
   and names its reason in the proxy log; the common ones are a metadata
   document host outside the allowlist and a `resource` value absent from the
   table.
4. **The token step** — a successful connection is not proof that the audience
   is right. Call the resource once; a token with the wrong audience is
   rejected there, not at the proxy.

A client that lists tools has completed steps 1 to 3. Only step 4 shows the
chain actually carries.

## Rollback before forward

Pin the image to a tag, never `latest`, and note the tag currently running
before changing it. The proxy holds no state beyond its configuration, so a
rollback is a tag change and a restart — with one exception: changing
`PROXY_SECRET_KEY` invalidates every refresh token already issued, and every
connected client has to authorize again. Treat that value as permanent for the
life of a deployment.

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
