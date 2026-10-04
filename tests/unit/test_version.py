# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""One version, everywhere it is stated.

The package version lives in ``cimd_proxy.__version__``; the wheel reads it
from there (hatch dynamic version), the FastAPI app announces it, and the
Sonar analysis is labelled with it. The release workflow additionally refuses a
tag that is not ``v`` plus this version.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

from cimd_proxy import __version__
from cimd_proxy.app import create_app

ROOT = Path(__file__).resolve().parents[2]


def test_version_is_semver() -> None:
    assert re.fullmatch(r"\d+\.\d+\.\d+", __version__)


def test_wheel_reads_the_package_version() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert "version" not in project["project"]
    assert project["project"]["dynamic"] == ["version"]
    assert project["tool"]["hatch"]["version"]["path"] == "src/cimd_proxy/__init__.py"


def test_app_announces_the_package_version(config) -> None:
    assert create_app(config).version == __version__


def test_sonar_analysis_carries_the_package_version() -> None:
    properties = (ROOT / "sonar-project.properties").read_text()
    assert f"sonar.projectVersion={__version__}\n" in properties


def test_readme_quick_start_pins_the_current_tag() -> None:
    tags = re.findall(r"ghcr\.io/kumbuka-ai/cimd-proxy:(v[\d.]+)", (ROOT / "README.md").read_text())
    assert tags == [f"v{__version__}"]
