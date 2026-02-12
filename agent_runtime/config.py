from __future__ import annotations

from pydantic import BaseModel
from dotenv import load_dotenv
import os

load_dotenv()


class Settings(BaseModel):
    opa_url: str = os.getenv("OPA_URL", "http://localhost:8181")
    default_baseline: str = os.getenv("DEFAULT_BASELINE", "B3")
    audit_log_path: str = os.getenv("AUDIT_LOG_PATH", "results/audit.jsonl")


settings = Settings()
