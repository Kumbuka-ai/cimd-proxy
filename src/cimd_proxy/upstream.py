# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""Upstream OIDC provider endpoints.

Today Keycloak is the only supported upstream, and its endpoint paths follow a
fixed convention off the issuer URL. When another provider is added, this
module grows a discriminating layer; do not anticipate that here.
"""

from __future__ import annotations


def authorize_url(issuer: str) -> str:
    return f"{issuer.rstrip('/')}/protocol/openid-connect/auth"


def token_url(issuer: str) -> str:
    return f"{issuer.rstrip('/')}/protocol/openid-connect/token"
