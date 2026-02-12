from __future__ import annotations

from typing import Any, Dict


def db_query_readonly(sql: str) -> Dict[str, Any]:
    return {"rows": [{"count": 42}], "query": sql}
