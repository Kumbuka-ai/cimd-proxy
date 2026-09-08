# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""Entrypoint for ``python -m cimd_proxy`` and the container CMD.

Reads the configuration from the environment, then hands the app to uvicorn.
"""

from __future__ import annotations

import uvicorn

from .app import create_app
from .config import load_config


def main() -> None:
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
