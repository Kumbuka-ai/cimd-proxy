# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""``pat-create``, ``pat-list`` and ``pat-revoke``: personal access tokens from a terminal.

Each command signs the owner in the way every MCP client does, and then makes
one call to the management endpoints with the access token that sign-in
produced:

1. The proxy is found from the resource's protected resource metadata
   (RFC 9728) unless ``--proxy`` names it, and its own metadata (RFC 8414) is
   read for the endpoints.
2. A loopback listener is opened on ``127.0.0.1`` with a port the operating
   system picks, and the command registers itself at ``/register`` (RFC 7591)
   with that redirect URI -- a public client, no secret (RFC 8252 sections 7.3
   and 8.3; the proxy ignores the port of a loopback redirect URI).
3. The browser is sent to ``/authorize`` with PKCE S256 and a fresh ``state``.
   The redirect back must carry that ``state`` and the proxy's ``iss``
   (RFC 9207); anything else ends the command before a token is used.
4. The code is redeemed at ``/token``; the access token is held in memory for
   the one management call and dropped. A refresh token, if one comes back, is
   discarded unread.

Nothing secret is written anywhere but the one place it is meant for: the
access token never leaves the process, and the personal access token
``pat-create`` creates is printed on stdout, once, and nowhere else -- not on
stderr, not in an error message, not in a file. No command takes a secret as an
argument.

This module imports the standard library and ``httpx`` only -- none of the
server's dependencies -- and ``python -m cimd_proxy.pat_cli create|list|revoke``
is the same as the three installed scripts.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import html
import os
import secrets
import sys
import threading
import webbrowser
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import ip_address
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

import httpx

ENV_PROXY = "CIMD_PAT_PROXY"
ENV_RESOURCE = "CIMD_PAT_RESOURCE"
DEFAULT_LOGIN_SCOPE = "openid"
DEFAULT_TIMEOUT_SECONDS = 300
CALLBACK_PATH = "/callback"
CLIENT_NAME = "cimd-proxy pat command line"

Browser = Callable[[str], None]


class CliError(Exception):
    """A refusal or failure the command reports on stderr before exiting non-zero."""


@dataclass(frozen=True, slots=True)
class Endpoints:
    issuer: str
    authorization: str
    token: str
    registration: str

    @property
    def pat_tokens(self) -> str:
        return f"{self.issuer}/pat/tokens"


@dataclass(frozen=True, slots=True)
class SignedIn:
    """The proxy's endpoints and the owner's access token, kept out of every ``repr``."""

    endpoints: Endpoints
    access_token: str = field(repr=False)

    @property
    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.access_token}"}


# --- discovery -------------------------------------------------------------


def _require_secure(url: str, what: str) -> str:
    """https, or http on a loopback address only: a bearer token never travels in clear."""

    parts = urlsplit(url)
    if parts.scheme == "https" and parts.hostname:
        return url.rstrip("/")
    if parts.scheme == "http" and _is_loopback(parts.hostname):
        return url.rstrip("/")
    raise CliError(f"{what} {url!r} must be an https URL")


def _is_loopback(host: str | None) -> bool:
    if host == "localhost":
        return True
    try:
        return ip_address(host or "").is_loopback
    except ValueError:
        return False


def _get_json(http: httpx.Client, url: str) -> dict[str, Any] | None:
    response = http.get(url, headers={"Accept": "application/json"})
    if response.status_code == 404:
        return None
    if response.status_code != 200:
        raise CliError(f"{url} answered HTTP {response.status_code}")
    try:
        document = response.json()
    except ValueError as exc:
        raise CliError(f"{url} did not answer with JSON") from exc
    if not isinstance(document, dict):
        raise CliError(f"{url} did not answer with a JSON object")
    return document


def discover_proxy(http: httpx.Client, resource: str) -> str:
    """The authorization server a resource names in its RFC 9728 metadata."""

    parts = urlsplit(resource)
    path = parts.path.rstrip("/")
    candidates = [f"/.well-known/oauth-protected-resource{path}"]
    if path:
        candidates.append("/.well-known/oauth-protected-resource")
    for well_known in candidates:
        document = _get_json(http, urlunsplit((parts.scheme, parts.netloc, well_known, "", "")))
        if document is None:
            continue
        if str(document.get("resource", "")).rstrip("/") != resource.rstrip("/"):
            raise CliError(
                f"the protected resource metadata at {parts.netloc}{well_known} "
                f"names another resource; pass --proxy"
            )
        servers = document.get("authorization_servers")
        if not isinstance(servers, list) or len(servers) != 1 or not isinstance(servers[0], str):
            raise CliError(
                f"{resource} does not name exactly one authorization server; pass --proxy"
            )
        return servers[0]
    raise CliError(f"{resource} publishes no protected resource metadata; pass --proxy")


def read_endpoints(http: httpx.Client, proxy: str) -> Endpoints:
    issuer = _require_secure(proxy, "the proxy URL")
    document = _get_json(http, f"{issuer}/.well-known/oauth-authorization-server")
    if document is None:
        raise CliError(f"{issuer} publishes no authorization server metadata")
    if str(document.get("issuer", "")).rstrip("/") != issuer:
        raise CliError(f"the metadata of {issuer} names another issuer")
    if "S256" not in document.get("code_challenge_methods_supported", []):
        raise CliError(f"{issuer} does not offer PKCE S256")
    try:
        return Endpoints(
            issuer=issuer,
            authorization=_require_secure(document["authorization_endpoint"], "authorization"),
            token=_require_secure(document["token_endpoint"], "token endpoint"),
            registration=_require_secure(document["registration_endpoint"], "registration"),
        )
    except (KeyError, TypeError) as exc:
        raise CliError(f"the metadata of {issuer} lacks an endpoint: {exc}") from exc


# --- the loopback redirect ---------------------------------------------------


class LoopbackReceiver:
    """Receives exactly one redirect on ``http://127.0.0.1:<ephemeral port>/callback``."""

    def __init__(self) -> None:
        self._received: dict[str, str] | None = None
        self._done = threading.Event()
        self._lock = threading.Lock()
        receiver = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 - the http.server hook name
                parts = urlsplit(self.path)
                if parts.path != CALLBACK_PATH:
                    self._answer(404, "Not found.")
                    return
                params = {k: v[0] for k, v in parse_qs(parts.query).items()}
                if receiver._accept(params):
                    self._answer(200, "Sign-in received. Return to the terminal.")
                else:
                    self._answer(409, "This sign-in has already been answered.")

            def _answer(self, status: int, text: str) -> None:
                body = (
                    "<!doctype html><meta charset=utf-8><title>pat</title>"
                    f"<p>{html.escape(text)}</p>"
                ).encode()
                self.send_response(status)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("Referrer-Policy", "no-referrer")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                # The default writes the request line -- code and state -- to stderr.
                return

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def redirect_uri(self) -> str:
        return f"http://127.0.0.1:{self._server.server_address[1]}{CALLBACK_PATH}"

    def _accept(self, params: dict[str, str]) -> bool:
        with self._lock:
            if self._received is not None:
                return False
            self._received = params
        self._done.set()
        return True

    def wait(self, timeout: float) -> dict[str, str] | None:
        self._done.wait(timeout)
        return self._received

    def __enter__(self) -> LoopbackReceiver:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._server.shutdown()
        self._server.server_close()


# --- sign-in -----------------------------------------------------------------


def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge.rstrip(b"=").decode("ascii")


def _refusal(response: httpx.Response) -> str:
    """The OAuth error of a refused call -- its two named fields and nothing else."""

    try:
        body = response.json()
    except ValueError:
        body = None
    if isinstance(body, dict) and isinstance(body.get("error"), str):
        description = body.get("error_description")
        detail = f": {description}" if isinstance(description, str) and description else ""
        return f"HTTP {response.status_code} {body['error']}{detail}"
    return f"HTTP {response.status_code}"


def check_redirect(received: dict[str, str], *, state: str, issuer: str) -> str:
    """The code of a redirect that answers *this* sign-in, or a refusal.

    The ``state`` must be the one this process sent (a redirect from another
    browser tab or an attacker's link is not this sign-in), and ``iss`` must name
    the proxy (RFC 9207: a mix-up with another authorization server).
    """

    if not secrets.compare_digest(received.get("state", ""), state):
        raise CliError("the sign-in came back with a foreign state; nothing was created")
    if received.get("iss", "").rstrip("/") != issuer:
        raise CliError("the sign-in came back from another issuer; nothing was created")
    if "error" in received:
        detail = received.get("error_description", "")
        raise CliError(
            f"the sign-in was refused: {received['error']}"
            + (f": {detail}" if detail else "")
            + "; nothing was created"
        )
    code = received.get("code")
    if not code:
        raise CliError("the sign-in came back without a code; nothing was created")
    return code


def register(http: httpx.Client, endpoints: Endpoints, redirect_uri: str) -> str:
    response = http.post(
        endpoints.registration,
        json={
            "redirect_uris": [redirect_uri],
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "client_name": CLIENT_NAME,
        },
    )
    if response.status_code != 201:
        raise CliError(f"registration refused: {_refusal(response)}")
    client_id = response.json().get("client_id")
    if not isinstance(client_id, str) or not client_id:
        raise CliError("registration returned no client_id")
    return client_id


def sign_in(
    http: httpx.Client,
    endpoints: Endpoints,
    *,
    resource: str,
    login_scope: str,
    timeout: float,
    open_browser: Browser,
) -> SignedIn:
    """The interactive authorization-code flow with PKCE, ending in an access token."""

    with LoopbackReceiver() as receiver:
        redirect_uri = receiver.redirect_uri
        client_id = register(http, endpoints, redirect_uri)
        verifier, challenge = _pkce_pair()
        state = secrets.token_urlsafe(32)
        query = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": state,
            "resource": resource,
        }
        if login_scope:
            query["scope"] = login_scope
        open_browser(f"{endpoints.authorization}?{urlencode(query)}")
        received = receiver.wait(timeout)

    if received is None:
        raise CliError(f"no sign-in arrived within {timeout:g} seconds; nothing was created")
    code = check_redirect(received, state=state, issuer=endpoints.issuer)

    response = http.post(
        endpoints.token,
        data={
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": verifier,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
        },
        headers={"Accept": "application/json"},
    )
    if response.status_code != 200:
        raise CliError(f"the token endpoint refused the code: {_refusal(response)}")
    access_token = response.json().get("access_token")
    if not isinstance(access_token, str) or not access_token:
        raise CliError("the token endpoint returned no access token")
    return SignedIn(endpoints=endpoints, access_token=access_token)


# --- the three commands ----------------------------------------------------


def create_token(http: httpx.Client, session: SignedIn, body: dict[str, Any]) -> dict[str, Any]:
    response = http.post(session.endpoints.pat_tokens, json=body, headers=session.headers)
    if response.status_code != 201:
        raise CliError(f"the proxy refused the token: {_refusal(response)}")
    created = response.json()
    if not isinstance(created.get("token"), str):
        raise CliError("the proxy answered without a token")
    return created


def list_tokens(http: httpx.Client, session: SignedIn) -> list[dict[str, Any]]:
    response = http.get(session.endpoints.pat_tokens, headers=session.headers)
    if response.status_code != 200:
        raise CliError(f"the proxy refused the listing: {_refusal(response)}")
    return list(response.json().get("tokens", []))


def revoke_token(http: httpx.Client, session: SignedIn, token_id: str) -> None:
    response = http.delete(f"{session.endpoints.pat_tokens}/{token_id}", headers=session.headers)
    if response.status_code != 204:
        raise CliError(f"the proxy refused the revocation: {_refusal(response)}")


def describe(created: dict[str, Any]) -> str:
    """The stderr line about a new token: its public fields, named one by one."""

    sets = ", ".join(created.get("scopes", [])) or "(none)"
    return (
        f"created personal access token {created.get('name')!r} (id {created.get('id')}) "
        f"for organization {created.get('tenant')}: permission sets {sets}; "
        f"resources {', '.join(created.get('resources', []))}; "
        f"expires {created.get('expires_at')}"
    )


def _table(tokens: list[dict[str, Any]]) -> str:
    rows = [("ID", "NAME", "ORGANIZATION", "SETS", "EXPIRES", "LAST USED", "STATE")]
    for t in tokens:
        rows.append(
            (
                str(t.get("id")),
                str(t.get("name")),
                str(t.get("tenant")),
                ",".join(t.get("scopes", [])) or "-",
                str(t.get("expires_at")),
                str(t.get("last_used_at") or "-"),
                "revoked" if t.get("revoked_at") else "active",
            )
        )
    widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
    return "\n".join("  ".join(c.ljust(w) for c, w in zip(r, widths, strict=True)) for r in rows)


# --- command lines -----------------------------------------------------------


def _common(prog: str, description: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=prog, description=description)
    parser.add_argument(
        "--resource",
        action="append",
        default=None,
        metavar="URL",
        help=f"protected resource the token is for; repeatable (env {ENV_RESOURCE})",
    )
    parser.add_argument(
        "--proxy",
        default=os.environ.get(ENV_PROXY) or None,
        metavar="URL",
        help=f"the cimd-proxy base URL (env {ENV_PROXY}); default: discovered from the "
        "resource's protected resource metadata (RFC 9728)",
    )
    parser.add_argument(
        "--login-scope",
        default=DEFAULT_LOGIN_SCOPE,
        metavar="SCOPE",
        help=f"scope of the interactive sign-in (default {DEFAULT_LOGIN_SCOPE!r})",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
        metavar="SECONDS",
        help=f"how long to wait for the sign-in (default {DEFAULT_TIMEOUT_SECONDS})",
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="print the sign-in URL instead of opening a browser",
    )
    return parser


def _create_parser() -> argparse.ArgumentParser:
    parser = _common(
        "pat-create",
        "Create a personal access token and print it on stdout, once. Without --set it "
        "carries every permission set you may hold.",
    )
    parser.add_argument("--name", required=True, help="a name for the token (1-100 characters)")
    parser.add_argument(
        "--set",
        dest="sets",
        action="append",
        default=[],
        metavar="SET",
        help="a permission set the token is limited to; repeatable",
    )
    parser.add_argument(
        "--expires-in-days", type=int, default=None, metavar="N", help="lifetime (default 90)"
    )
    parser.add_argument(
        "--allow-long-lifetime",
        action="store_true",
        help="permit a lifetime above 365 days",
    )
    parser.add_argument(
        "--organization",
        default=None,
        help="the organization to bind the token to, when you belong to several",
    )
    return parser


def _list_parser() -> argparse.ArgumentParser:
    return _common("pat-list", "List your personal access tokens (never their values).")


def _revoke_parser() -> argparse.ArgumentParser:
    parser = _common("pat-revoke", "Revoke one of your personal access tokens.")
    parser.add_argument("id", help="the token id, as pat-list shows it")
    return parser


def _default_browser(url: str) -> None:
    print(f"Sign in to continue. If no browser opens, visit:\n  {url}", file=sys.stderr)
    webbrowser.open(url)


def _print_only(url: str) -> None:
    print(f"Sign in at:\n  {url}", file=sys.stderr)


def _resources(args: argparse.Namespace) -> list[str]:
    resources = args.resource or [r for r in os.environ.get(ENV_RESOURCE, "").split() if r]
    if not resources:
        raise CliError(f"name the protected resource with --resource or {ENV_RESOURCE}")
    return [_require_secure(r, "the resource") for r in resources]


def _session(
    http: httpx.Client, args: argparse.Namespace, open_browser: Browser | None
) -> tuple[SignedIn, list[str]]:
    resources = _resources(args)
    proxy = args.proxy or discover_proxy(http, resources[0])
    endpoints = read_endpoints(http, proxy)
    browser = open_browser or (_print_only if args.no_browser else _default_browser)
    session = sign_in(
        http,
        endpoints,
        resource=resources[0],
        login_scope=args.login_scope,
        timeout=args.timeout,
        open_browser=browser,
    )
    return session, resources


def _run(
    parser: argparse.ArgumentParser,
    action: Callable[[httpx.Client, argparse.Namespace], None],
    argv: Sequence[str] | None,
    http: httpx.Client | None,
) -> int:
    args = parser.parse_args(argv)
    owned = http is None
    client = http or httpx.Client(timeout=30.0, follow_redirects=False)
    try:
        action(client, args)
    except CliError as exc:
        print(f"{parser.prog}: {exc}", file=sys.stderr)
        return 1
    except httpx.HTTPError as exc:
        print(
            f"{parser.prog}: the proxy could not be reached: {type(exc).__name__}", file=sys.stderr
        )
        return 1
    finally:
        if owned:
            client.close()
    return 0


def create_main(
    argv: Sequence[str] | None = None,
    *,
    http: httpx.Client | None = None,
    open_browser: Browser | None = None,
) -> int:
    def action(client: httpx.Client, args: argparse.Namespace) -> None:
        session, resources = _session(client, args, open_browser)
        body: dict[str, Any] = {"name": args.name, "resources": resources}
        if args.sets:
            body["scopes"] = args.sets
        else:
            body["all_permitted_scopes"] = True
        if args.expires_in_days is not None:
            body["expires_in_days"] = args.expires_in_days
        if args.allow_long_lifetime:
            body["allow_long_lifetime"] = True
        if args.organization:
            body["organization"] = args.organization
        created = create_token(client, session, body)
        print(describe(created), file=sys.stderr)
        sys.stdout.write(created["token"] + "\n")
        sys.stdout.flush()

    return _run(_create_parser(), action, argv, http)


def list_main(
    argv: Sequence[str] | None = None,
    *,
    http: httpx.Client | None = None,
    open_browser: Browser | None = None,
) -> int:
    def action(client: httpx.Client, args: argparse.Namespace) -> None:
        session, _ = _session(client, args, open_browser)
        print(_table(list_tokens(client, session)))

    return _run(_list_parser(), action, argv, http)


def revoke_main(
    argv: Sequence[str] | None = None,
    *,
    http: httpx.Client | None = None,
    open_browser: Browser | None = None,
) -> int:
    def action(client: httpx.Client, args: argparse.Namespace) -> None:
        session, _ = _session(client, args, open_browser)
        revoke_token(client, session, args.id)
        print(f"revoked {args.id}", file=sys.stderr)

    return _run(_revoke_parser(), action, argv, http)


def create() -> None:  # pragma: no cover - console-script shim
    raise SystemExit(create_main())


def list_() -> None:  # pragma: no cover - console-script shim
    raise SystemExit(list_main())


def revoke() -> None:  # pragma: no cover - console-script shim
    raise SystemExit(revoke_main())


if __name__ == "__main__":  # pragma: no cover - python -m cimd_proxy.pat_cli
    commands = {"create": create_main, "list": list_main, "revoke": revoke_main}
    if len(sys.argv) < 2 or sys.argv[1] not in commands:
        raise SystemExit(f"usage: {sys.argv[0]} create|list|revoke [options]")
    raise SystemExit(commands[sys.argv[1]](sys.argv[2:]))
