from __future__ import annotations

from pydantic import BaseModel
from dotenv import load_dotenv
import os

load_dotenv()


class Settings(BaseModel):
    opa_url: str = os.getenv("OPA_URL", "http://localhost:8181")
    default_baseline: str = os.getenv("DEFAULT_BASELINE", "B3")
    audit_log_path: str = os.getenv("AUDIT_LOG_PATH", "results/audit.jsonl")
    http_adapter: str = os.getenv("HTTP_ADAPTER", "mock")
    http_timeout_ms: int = int(os.getenv("HTTP_TIMEOUT_MS", "5000"))
    http_allow_redirects: bool = os.getenv("HTTP_ALLOW_REDIRECTS", "false").lower() == "true"
    http_max_redirects: int = int(os.getenv("HTTP_MAX_REDIRECTS", "0"))
    metrics_enabled: bool = os.getenv("METRICS_ENABLED", "true").lower() == "true"
    metrics_path: str = os.getenv("METRICS_PATH", "/metrics")


settings = Settings()
