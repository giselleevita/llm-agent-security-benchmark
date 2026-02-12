# Observability

## Audit Logging
Audit events are emitted as JSON Lines to `results/audit.jsonl`.

### Event fields
- `request_id`
- `correlation_id`
- `scenario_id`
- `tool_name`
- `decision`
- `reason`
- `denial_reason_code`
- `policy_id`
- `policy_version`
- `policy_hash`
- `risk_score`
- `latency_ms`
- `ts`

## Metrics
Runtime exports Prometheus-compatible metrics at `/metrics` (configurable with `METRICS_PATH`).

### Metrics emitted
- `tool_gateway_decisions_total{decision=...}`
- `tool_gateway_tool_calls_total{tool=...}`
- `tool_gateway_latency_ms_bucket{tool=...,le=...}`

## Operational Notes
- Metrics are in-memory and process-local.
- For multi-instance deployment, scrape per instance and aggregate externally.
