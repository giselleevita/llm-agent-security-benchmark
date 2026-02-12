# Architecture

## High-level idea
The LLM agent is treated as **untrusted**. It can propose tool calls, but a **Tool Gateway (PEP)** enforces policy decisions from **OPA (PDP)**.

## Components
- **Orchestrator**: step loop; produces structured tool-call proposals.
- **Tool Gateway (PEP)**: validates, consults PDP, enforces allow/deny/approval, logs audit.
- **OPA (PDP)**: policy-as-code; returns `{allow, requires_approval, reason}`.
- **Tools**: deterministic mocks (`http_get`, `create_ticket`, doc store).
- **Benchmark Harness**: runs scenarios across baselines and computes metrics.
- **CI Gate**: fails builds if security regresses.

## Dataflow
```mermaid
flowchart LR
  U[User/Scenario] --> O[Orchestrator]
  O -->|ToolCallRequest| G[Tool Gateway (PEP)]
  G -->|Decision Input| P[OPA (PDP)]
  P -->|allow/deny/approval| G
  G -->|execute| T[Tools]
  T --> G
  G -->|ToolCallResult| O
  G --> A[Audit Log]
  B[Benchmark Runner] --> O
  B --> R[results/run.json + summary.json]
  CI[CI Gate] --> R
```

## Trust boundaries

**Untrusted**: LLM outputs, retrieved content, user input.

**Trusted**: Gateway enforcement, OPA policy evaluation, tool implementations (mocked/deterministic).
