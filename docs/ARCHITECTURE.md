# Architecture

```mermaid
flowchart LR
  U["Task / Scenario"] --> O["Orchestrator"]
  O --> G["Tool Gateway (PEP)"]
  G --> P["OPA (PDP)"]
  P --> G
  G --> T["Tool Adapters"]
  G --> A["Audit JSONL"]
  B["Benchmark Runner"] --> O
  B --> R["summary.json + comparison + report"]
```

## Components
- `agent_runtime/`: API runtime, orchestrator, audit and metrics.
- `gateway/`: schema validation, PDP calls, policy enforcement decisions.
- `policies/`: Rego policy bundle and OPA tests.
- `tools/`: deterministic adapters + optional hardened real HTTP adapter.
- `benchmark/`: scenario execution, scoring, schema validation.
