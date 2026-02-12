from __future__ import annotations

from agent_runtime.metrics import MetricsCollector


def test_metrics_render_prometheus() -> None:
    collector = MetricsCollector()
    collector.inc("tool_gateway_decisions_total", "allowed")
    collector.inc("tool_gateway_tool_calls_total", "http_get")
    collector.observe_latency("http_get", 12.5)

    text = collector.render_prometheus()
    assert "tool_gateway_decisions_total" in text
    assert 'decision="allowed"' in text
    assert 'tool="http_get"' in text
