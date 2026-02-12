from __future__ import annotations

import threading
from collections import Counter
from typing import Tuple


class MetricsCollector:
    """Small in-memory Prometheus-style metrics collector."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: Counter[Tuple[str, str]] = Counter()
        self._latency_buckets: Counter[Tuple[str, str]] = Counter()
        self._bucket_edges = (5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000)

    def inc(self, name: str, label: str, n: int = 1) -> None:
        with self._lock:
            self._counters[(name, label)] += n

    def observe_latency(self, tool: str, latency_ms: float) -> None:
        bucket = self._bucket_for(latency_ms)
        with self._lock:
            self._latency_buckets[(tool, bucket)] += 1

    def _bucket_for(self, latency_ms: float) -> str:
        for edge in self._bucket_edges:
            if latency_ms <= edge:
                return str(edge)
        return "+Inf"

    def render_prometheus(self) -> str:
        lines = []
        lines.append("# TYPE tool_gateway_decisions_total counter")
        for (name, label), value in sorted(self._counters.items()):
            if name != "tool_gateway_decisions_total":
                continue
            lines.append(
                f'tool_gateway_decisions_total{{decision="{label}"}} {value}'
            )

        lines.append("# TYPE tool_gateway_tool_calls_total counter")
        for (name, label), value in sorted(self._counters.items()):
            if name != "tool_gateway_tool_calls_total":
                continue
            lines.append(f'tool_gateway_tool_calls_total{{tool="{label}"}} {value}')

        lines.append("# TYPE tool_gateway_latency_ms_bucket counter")
        for (tool, bucket), value in sorted(self._latency_buckets.items()):
            lines.append(
                f'tool_gateway_latency_ms_bucket{{tool="{tool}",le="{bucket}"}} {value}'
            )

        return "\n".join(lines) + "\n"


metrics = MetricsCollector()
