# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""Entrypoint for ``python -m cimd_proxy`` and the container CMD.

Reads the configuration from the environment, then hands the app to uvicorn.
``python -m cimd_proxy migrate`` applies the personal-access-token schema
migrations instead (see :mod:`cimd_proxy.migrate`).
"""

from __future__ import annotations

import sys

import uvicorn

from .app import create_app
from .config import load_config


def main(argv: list[str] | None = None) -> None:
    args = sys.argv[1:] if argv is None else argv
    if args == ["migrate"]:
        from .migrate import main as migrate_main

        raise SystemExit(migrate_main())
    if args:
        raise SystemExit(f"unknown arguments {args!r}; the only subcommand is 'migrate'")
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
