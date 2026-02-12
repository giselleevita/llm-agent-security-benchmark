# Threat Model

## Scope
This model covers the runtime and benchmark in this repository:
`Orchestrator -> Tool Gateway (PEP) -> OPA (PDP) -> Tool adapters -> Audit/Results`.

## Trust Boundaries
1. **Untrusted model/planner output**
   - Input: tool proposals from orchestrator/planner.
   - Boundary: `gateway/pep.py` (policy enforcement).
2. **Policy decision boundary**
   - Input: policy context (`tool`, args, taint, risk, env, ablation).
   - Boundary: `gateway/pdp_client.py` -> `policies/rego/*`.
3. **Tool execution boundary**
   - Input: allowlisted and validated tool calls only.
   - Boundary: `tools/registry.py` + adapter implementations.
4. **Observability boundary**
   - Input: decision events and benchmark output.
   - Boundary: `agent_runtime/audit.py`, `results/*.json`.

## Assets
- Tool execution integrity (no unauthorized actions).
- Data confidentiality (prevent canary/secret leakage).
- Policy integrity (deterministic allow/deny/approval decisions).
- Audit integrity (forensic-quality event trail).
- Benchmark integrity (reproducible outputs and metadata).

## Attacker Model
- Prompt injector controlling user input.
- Retrieval injector controlling document snippets.
- Tool misuse adversary targeting unsafe domains/paths/projects.
- Exfiltration adversary attempting canary/secret leakage.
- SSRF adversary attempting metadata/private network access.

## Attack Surfaces
- Tool name and arguments.
- URL authority/path parsing and normalization.
- Domain/path allowlist bypass attempts.
- Approval bypass paths.
- Output leakage channels (tool payload, final output, audit artifacts).

## Mitigations Implemented
- Tool allowlisting and unknown tool denial.
- Policy-based parameter constraints (domain/path/project/body length).
- Canary detection and deny policy.
- Approval gating (`requires_approval`) for high-risk actions.
- Correlation IDs and structured JSONL audit.
- Deterministic benchmark baselines (B0-B3) and CI thresholds.

## Known Limitations
- Default runtime uses deterministic mock HTTP adapter (real network adapter is optional).
- DNS rebinding protection is best-effort in the optional real adapter.
- Punycode domains are denied conservatively; allow-by-exception is not implemented.
- No cryptographic signing of audit artifacts.

## Out of Scope
- Model training attacks / poisoning.
- Infrastructure side-channels.
- Endpoint exploit payload development.
- Handling real production secrets/PII.
