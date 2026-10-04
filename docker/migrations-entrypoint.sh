#!/bin/sh
# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0
#
# Entrypoint of the cimd-proxy-migrations image.
#
# NOT CONFIGURED MEANS DOING NOTHING, NOT FAILING. Personal access tokens are an
# optional feature of the proxy, and a deployment that does not use them still
# runs this image when the proxy waits for it to complete. With no migrator
# credentials at all it therefore exits 0 and says so: a failure here would
# hold back the proxy, and with it every interactive sign-in, for a feature
# nobody switched on.
#
# HALF CONFIGURED IS A FAILURE. One of FLYWAY_USER and FLYWAY_PASSWORD without
# the other is a mistake in the deployment, not a decision to leave the
# feature off, and it fails loudly.
#
# Flyway substitutes placeholders as text, so the two identifiers that reach
# the SQL (the schema and the runtime role) are checked here before Flyway
# starts: plain lower-case identifiers of at most 63 characters, nothing that
# could close a quote.
set -eu

me="cimd-proxy-migrations"
user="${FLYWAY_USER:-}"
password="${FLYWAY_PASSWORD:-}"

if [ -z "$user" ] && [ -z "$password" ]; then
    echo "$me: FLYWAY_USER and FLYWAY_PASSWORD are empty -- personal access tokens" \
        "are not configured; nothing to migrate"
    exit 0
fi
if [ -z "$user" ] || [ -z "$password" ]; then
    echo "$me: only one of FLYWAY_USER and FLYWAY_PASSWORD is set; set both or neither" >&2
    exit 2
fi
if [ -z "${FLYWAY_URL:-}" ]; then
    echo "$me: FLYWAY_URL is required when the migrator credentials are set" >&2
    exit 2
fi

identifier() {
    # $1 name of the variable, $2 its value
    case "$2" in
        '' | [!a-z_]* | *[!a-z0-9_]*)
            echo "$me: $1 '$2' is not a plain lower-case identifier" >&2
            exit 2
            ;;
    esac
    if [ "${#2}" -gt 63 ]; then
        echo "$me: $1 is longer than 63 characters" >&2
        exit 2
    fi
}

identifier FLYWAY_SCHEMAS "${FLYWAY_SCHEMAS:-}"
identifier FLYWAY_PLACEHOLDERS_APP_ROLE "${FLYWAY_PLACEHOLDERS_APP_ROLE:-}"

exec flyway "$@"
