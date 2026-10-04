#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0
#
# deploy/pat-smoke.sh — a personal access token end to end, from outside.
#
#   1. create a token for one permission set        POST   <proxy>/pat/tokens
#   2. exchange it for a short access token         POST   <proxy>/token
#   3. call a tool of the MCP resource with it      must succeed
#   4. call a tool the set does not permit          must be refused, with a given reason
#   5. revoke the token                             DELETE <proxy>/pat/tokens/<id>
#   6. exchange it again                            must be refused
#
# A token created here is revoked on every exit, also when a step fails.
# Nothing secret is printed: the owner's bearer token, the personal access
# token and the short token travel to curl through files in a private
# temporary directory, never as arguments (which `ps` shows) and never to
# stdout. Exit 0 when every step held, 1 otherwise.
#
# Environment:
#   PAT_SMOKE_BEARER        the owner's access token from an INTERACTIVE sign-in
#                           (it must carry `sid`, and `organization` naming the
#                           organization the token is to be bound to)
#   PAT_SMOKE_PROXY         the proxy's public URL, e.g. https://mcp-auth.example
#   PAT_SMOKE_RESOURCE      the MCP resource, e.g. https://mcp.example/mcp
#   PAT_SMOKE_SCOPES        the permission set(s), space separated
#   PAT_SMOKE_ORGANIZATION  optional: the organization, when the owner has several
#   PAT_SMOKE_READ_TOOL     tool that must succeed, and its JSON arguments in
#   PAT_SMOKE_READ_ARGS     PAT_SMOKE_READ_ARGS (default {})
#   PAT_SMOKE_REFUSED_TOOL  tool that must be refused, its JSON arguments, and
#   PAT_SMOKE_REFUSED_ARGS  a text the refusal must contain
#   PAT_SMOKE_REFUSED_REASON
set -uo pipefail

die() { echo "pat-smoke: $*" >&2; exit 1; }
for v in PAT_SMOKE_BEARER PAT_SMOKE_PROXY PAT_SMOKE_RESOURCE PAT_SMOKE_SCOPES \
         PAT_SMOKE_READ_TOOL PAT_SMOKE_REFUSED_TOOL PAT_SMOKE_REFUSED_ARGS \
         PAT_SMOKE_REFUSED_REASON; do
  [[ -n "${!v:-}" ]] || die "$v is required"
done
for tool in curl jq; do command -v "$tool" >/dev/null 2>&1 || die "$tool is required"; done
PROXY="${PAT_SMOKE_PROXY%/}"
RESOURCE="$PAT_SMOKE_RESOURCE"
READ_ARGS="${PAT_SMOKE_READ_ARGS:-{\}}"

WORK="$(mktemp -d)"
FAILS=0
PAT_ID=""
REVOKED=0
OWNER_AUTH="$WORK/owner-auth"
printf 'Authorization: Bearer %s\n' "$PAT_SMOKE_BEARER" > "$OWNER_AUTH"

step() {  # step DESCRIPTION 0|1 [DETAIL]
  if [[ "$2" == 0 ]]; then echo "ok   - $1"; else echo "FAIL - $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi
}

revoke() {  # -> HTTP status
  curl -sS -o /dev/null -w '%{http_code}' -X DELETE -H @"$OWNER_AUTH" "$PROXY/pat/tokens/$PAT_ID"
}

finish() {
  if [[ -n "$PAT_ID" && "$REVOKED" == 0 ]]; then
    echo "pat-smoke: revoking the token created by this run: HTTP $(revoke)"
  fi
  rm -rf "$WORK"
}
trap finish EXIT

exchange() {  # -> HTTP status; response in $WORK/exchange
  curl -sS -o "$WORK/exchange" -w '%{http_code}' -X POST "$PROXY/token" \
    --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
    --data-urlencode "subject_token@$WORK/pat" \
    --data-urlencode "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
    --data-urlencode "resource=$RESOURCE"
}

# An MCP call over streamable HTTP. The answer may be JSON or an event stream;
# for the stream, the JSON-RPC message is the data line that carries our id.
mcp() {  # mcp ID METHOD PARAMS -> JSON-RPC response on stdout
  local id="$1" headers=(-H @"$WORK/short-auth" -H 'Content-Type: application/json'
    -H 'Accept: application/json, text/event-stream')
  [[ -s "$WORK/session" ]] && headers+=(-H @"$WORK/session")
  [[ -s "$WORK/protocol" ]] && headers+=(-H @"$WORK/protocol")
  jq -c -n --argjson id "$id" --arg m "$2" --argjson p "$3" \
    '{jsonrpc: "2.0", id: $id, method: $m, params: $p}' \
    | curl -sS -D "$WORK/headers" -o "$WORK/mcp" -X POST "${headers[@]}" --data-binary @- \
      "$RESOURCE" >/dev/null || return 1
  if grep -qi '^content-type: *text/event-stream' "$WORK/headers"; then
    sed -n 's/^data: *//p' "$WORK/mcp" | jq -c --argjson id "$id" 'select(.id == $id)' | head -1
  else
    cat "$WORK/mcp"
  fi
}

# --- 1. create ----------------------------------------------------------------
create_body="$(jq -c -n --arg r "$RESOURCE" --arg s "$PAT_SMOKE_SCOPES" \
  --arg o "${PAT_SMOKE_ORGANIZATION:-}" --arg n "smoke-$(date -u +%Y%m%dT%H%M%SZ)" \
  '{name: $n, resources: [$r], scopes: ($s | split(" ") | map(select(. != ""))),
    expires_in_days: 1} + (if $o == "" then {} else {organization: $o} end)')"
code="$(curl -sS -o "$WORK/created" -w '%{http_code}' -X POST -H @"$OWNER_AUTH" \
  -H 'Content-Type: application/json' --data-binary "$create_body" "$PROXY/pat/tokens")"
if [[ "$code" == 201 ]]; then
  jq -j .token "$WORK/created" > "$WORK/pat"   # -j: no newline, the file is form data
  PAT_ID="$(jq -r .id "$WORK/created")"
  step "create a token for [$PAT_SMOKE_SCOPES] bound to $(jq -r .tenant "$WORK/created")" 0
else
  step "create a token" 1 "HTTP $code $(jq -c 'del(.token)' "$WORK/created" 2>/dev/null)"
  exit 1
fi
rm -f "$WORK/created"

# --- 2. exchange --------------------------------------------------------------
code="$(exchange)"
if [[ "$code" == 200 ]]; then
  printf 'Authorization: Bearer %s\n' "$(jq -r .access_token "$WORK/exchange")" > "$WORK/short-auth"
  step "exchange it: a short token for $(jq -r .expires_in "$WORK/exchange") s" \
    "$(jq -e 'has("refresh_token") | not' "$WORK/exchange" >/dev/null && echo 0 || echo 1)"
else
  step "exchange it" 1 "HTTP $code $(jq -c '{error, error_description}' "$WORK/exchange" 2>/dev/null)"
  exit 1
fi
rm -f "$WORK/exchange"

# --- 3. a permitted call ----------------------------------------------------------
init="$(mcp 1 initialize '{"protocolVersion": "2025-06-18", "capabilities": {},
  "clientInfo": {"name": "pat-smoke", "version": "1"}}')"
if [[ "$(jq -r '.result.protocolVersion // empty' <<<"$init")" != "" ]]; then
  grep -i '^mcp-session-id:' "$WORK/headers" | tr -d '\r' > "$WORK/session"
  printf 'MCP-Protocol-Version: %s\n' "$(jq -r .result.protocolVersion <<<"$init")" \
    > "$WORK/protocol"
  step "MCP initialize at $RESOURCE" 0
else
  step "MCP initialize at $RESOURCE" 1 "$(head -c 300 "$WORK/mcp")"
  exit 1
fi
mcp 2 notifications/initialized '{}' >/dev/null || true
read_reply="$(mcp 3 tools/call "$(jq -c -n --arg t "$PAT_SMOKE_READ_TOOL" --argjson a "$READ_ARGS" \
  '{name: $t, arguments: $a}')")"
step "$PAT_SMOKE_READ_TOOL succeeds" "$(jq -e '.result and (.result.isError | not)' \
  <<<"$read_reply" >/dev/null 2>&1 && echo 0 || echo 1)" "$(head -c 300 <<<"$read_reply")"

# --- 4. a call outside the set ------------------------------------------------------
refused_reply="$(mcp 4 tools/call "$(jq -c -n --arg t "$PAT_SMOKE_REFUSED_TOOL" \
  --argjson a "$PAT_SMOKE_REFUSED_ARGS" '{name: $t, arguments: $a}')")"
step "$PAT_SMOKE_REFUSED_TOOL is refused with $PAT_SMOKE_REFUSED_REASON" "$(jq -e \
  --arg why "$PAT_SMOKE_REFUSED_REASON" '(.error != null or .result.isError == true)
    and (tostring | contains($why))' <<<"$refused_reply" >/dev/null 2>&1 && echo 0 || echo 1)" \
  "$(head -c 300 <<<"$refused_reply")"

# --- 5. revoke, 6. refused afterwards ---------------------------------------------------
code="$(revoke)"
[[ "$code" == 204 ]] && REVOKED=1
step "revoke it" "$([[ "$code" == 204 ]] && echo 0 || echo 1)" "HTTP $code"
code="$(exchange)"
step "an exchange after revocation is refused" "$([[ "$code" == 400 ]] \
  && jq -e '.error == "invalid_grant" and (has("access_token") | not)' "$WORK/exchange" \
  >/dev/null && echo 0 || echo 1)" "HTTP $code"

echo
if [[ "$FAILS" == 0 ]]; then echo "pat-smoke: ALL STEPS HELD"; exit 0; fi
echo "pat-smoke: $FAILS STEP(S) FAILED"; exit 1
