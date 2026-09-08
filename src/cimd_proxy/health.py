# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""Liveness endpoint.

No authentication, no data-store touch — just a constant response so a health
probe can never accidentally exercise the auth path.
"""
