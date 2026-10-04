# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""The schema migrations of the personal-access-token store, as Flyway files.

Flyway applies them, from the ``cimd-proxy-migrations`` image, which copies the
files of this directory; the proxy never runs one. It reads them only to know
which schema version it needs (:func:`latest_version`), and refuses to start
while the database's Flyway history is behind that (see
:meth:`cimd_proxy.pat_store.PostgresPatStore.check_schema`).

An applied migration is never edited: a change is a new file, and it only adds
(nullable or defaulted columns, new tables, new grants), so the previous image
still runs against the new schema and an image rollback needs no database
rollback.
"""

from __future__ import annotations

import re
from pathlib import Path

DIRECTORY = Path(__file__).parent
_FILE = re.compile(r"^V(\d+)__[a-z0-9_]+\.sql$")


def versions() -> list[int]:
    """The versions of the migration files, which must run 1..n without gaps."""

    found = sorted(int(m.group(1)) for e in DIRECTORY.iterdir() if (m := _FILE.match(e.name)))
    if found != list(range(1, len(found) + 1)):
        raise RuntimeError(f"migration versions must run 1..n without gaps, found {found}")
    return found


def latest_version() -> int:
    return len(versions())
