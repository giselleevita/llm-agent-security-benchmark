from __future__ import annotations

import base64
from pydantic import BaseModel
from typing import Any, List


class Taint(BaseModel):
    from_user: bool = False
    from_retrieved: bool = False
    contains_canary: bool = False


def stringify(obj: Any) -> str:
    """Convert any object to a searchable string representation."""
    if obj is None:
        return ""
    if isinstance(obj, (str, int, float, bool)):
        return str(obj)
    if isinstance(obj, dict):
        return " ".join(stringify(v) for v in obj.values())
    if isinstance(obj, list):
        return " ".join(stringify(v) for v in obj)
    return str(obj)


def detect_canary(payload: Any, canaries: List[str]) -> bool:
    """
    Detect canary tokens in payload, including:
    - Direct substring matches (case-insensitive)
    - Base64-encoded variants
    - Partial matches (to catch obfuscation attempts)
    """
    blob = stringify(payload).lower()
    
    for canary in canaries:
        canary_lower = canary.lower()
        
        # Direct match
        if canary_lower in blob:
            return True
        
        # Base64 encoded
        try:
            canary_b64 = base64.b64encode(canary.encode()).decode()
            if canary_b64.lower() in blob:
                return True
        except Exception:
            pass
        
        # Check for partial matches only when multiple meaningful parts are present.
        # Require at least two parts (len >= 4) to avoid false positives on words like "canary_detected".
        parts = [p for p in canary_lower.split("_") if len(p) >= 4]
        if len(parts) >= 2 and all(part in blob for part in parts):
            return True
    
    return False
