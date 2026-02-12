# Portfolio Summary

## CV bullets
- Built a policy-enforced LLM agent runtime (PEP/PDP with OPA) that blocks unsafe tool calls.
- Implemented benchmark baselines (B0-B3) with measurable security outcomes and CI gating.
- Added SSRF-focused URL controls and regression tests for authority/path/domain bypasses.
- Introduced auditable decision telemetry (correlation IDs, reason codes, policy metadata).
- Delivered reproducible result schema + HTML reporting for enterprise review readiness.

## Interview talking points
1. Why policy-as-code is required beyond prompt-only guardrails.
2. Trade-offs between safety and utility across B0-B3 baselines.
3. How SSRF bypass classes were converted into automated regressions.
4. How audit and metrics support incident response and governance.
5. How deterministic benchmarking supports security CI gates.

## Why this is enterprise-grade
- Explicit decision boundary outside the LLM.
- Reproducible metrics with schema and CI thresholds.
- Defense-in-depth (allowlists, taint/canary checks, approvals, telemetry).
- Reviewable policy tests and implementation-level hardening controls.
