# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""Entrypoint for ``python -m cimd_proxy`` and the container CMD.

Reads the configuration from the environment, then hands the app to uvicorn.
There are no subcommands: the personal-access-token schema is migrated by the
``cimd-proxy-migrations`` image (see :mod:`cimd_proxy.migrations`).
"""

from __future__ import annotations

import sys

import uvicorn

from .app import create_app
from .config import load_config


def main(argv: list[str] | None = None) -> None:
    args = sys.argv[1:] if argv is None else argv
    if args:
        raise SystemExit(
            f"unknown arguments {args!r}; the proxy takes none "
            "(schema migrations run from the cimd-proxy-migrations image)"
        )
    config = load_config()
    app = create_app(config)
    uvicorn.run(
        app,
        host=config.bind_host,
        port=config.port,
        log_level=config.log_level.lower(),
        access_log=True,
    )


if __name__ == "__main__":
    main()
