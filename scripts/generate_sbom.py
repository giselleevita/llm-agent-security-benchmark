from __future__ import annotations

import json
import platform
import re
import sys
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path
from typing import Any


PROJECT_NAME = "secure-agent-runtime-benchmark"
PROJECT_VERSION = "1.0.0+thesis"


def _pypi_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _component(dist: metadata.Distribution) -> dict[str, str]:
    name = dist.metadata.get("Name") or dist.metadata.get("Summary") or "unknown"
    version = dist.version
    normalized = _pypi_name(name)
    return {
        "type": "library",
        "name": name,
        "version": version,
        "purl": f"pkg:pypi/{normalized}@{version}",
    }


def build_sbom() -> dict[str, Any]:
    components = sorted(
        (_component(dist) for dist in metadata.distributions()),
        key=lambda item: (item["name"].lower(), item["version"]),
    )
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc)
            .replace(microsecond=0)
            .isoformat(),
            "component": {
                "type": "application",
                "name": PROJECT_NAME,
                "version": PROJECT_VERSION,
            },
            "tools": [
                {
                    "vendor": "local",
                    "name": "scripts/generate_sbom.py",
                    "version": "1",
                }
            ],
            "properties": [
                {"name": "python.version", "value": platform.python_version()},
                {"name": "python.implementation", "value": platform.python_implementation()},
            ],
        },
        "components": components,
    }


def main() -> None:
    out_path = Path(sys.argv[1] if len(sys.argv) > 1 else "artifacts/sbom.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(build_sbom(), indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
