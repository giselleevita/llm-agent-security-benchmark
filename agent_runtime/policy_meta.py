from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def compute_policy_hash() -> str:
    root = _repo_root()
    rego_dir = root / "policies" / "rego"
    data_path = root / "policies" / "data" / "policy_data.json"

    h = hashlib.sha256()
    for p in sorted(rego_dir.glob("*.rego")):
        h.update(p.name.encode("utf-8"))
        h.update(p.read_bytes())

    if data_path.exists():
        h.update(data_path.name.encode("utf-8"))
        h.update(data_path.read_bytes())

    return h.hexdigest()


def load_policy_meta() -> Dict[str, Any]:
    data_path = _repo_root() / "policies" / "data" / "policy_data.json"
    policy_id = "agent-policy"
    policy_version = "unknown"

    if data_path.exists():
        data = json.loads(data_path.read_text(encoding="utf-8"))
        settings = data.get("settings") or {}
        policy_id = str(settings.get("policy_id", policy_id))
        policy_version = str(settings.get("policy_version", policy_version))

    return {
        "policy_id": policy_id,
        "policy_version": policy_version,
        "policy_hash": compute_policy_hash(),
    }
