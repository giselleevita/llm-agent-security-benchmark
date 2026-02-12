# Enterprise Security Review (Consultancy Lens)

Date: 2026-02-12
Reviewer role: Senior Security Engineer + Backend Architect
Scope: `/Users/yusaf/Desktop/gigi uni/llm-agent-security-benchmark` only

## Phase A - Recovery and grounding

### Recovery outcome
- SSH clone failed on this machine (`Permission denied (publickey)`), fallback HTTPS used.
- Remote source: `https://github.com/giselleevita/llm-agent-security-benchmark.git`
- Current commit: `15ddcbd999a05122f63b2b7442064edc898d3955`
- Branch: `codex/recovery-baseline`
- Integrity caveat: remote currently contains only `README.md`; project files were restored from local Cursor edit history snapshots.

### Environment snapshot
- Python packaging: `pyproject.toml` present.
- Runtime config: `agent_runtime/config.py`.
- Compose and OPA wiring files present: `docker-compose.yml`, `gateway/pdp_client.py`, `policies/rego/agent_policy.rego`.
- CI gate present: `.github/workflows/security_eval.yml`, `ci/thresholds.yaml`.
- Tooling gap on this host: `docker` and `opa` binaries unavailable, so B3 runtime execution cannot be validated live in this environment.

## Phase 1 - Repository inventory

| Component | Primary files | Execution role | Integration points |
|---|---|---|---|
| Orchestrator / agent interface | `agent_runtime/orchestrator.py`, `agent_runtime/main.py` | Deterministic planner creates tool proposals; FastAPI exposes `/run` | Calls `ToolGateway.execute()` with tool request metadata and taint |
| Tool gateway (PEP) | `gateway/pep.py`, `gateway/validators.py` | Enforces B0-B3 behavior, schema validation, policy decision path, audit emission | Uses `PDPClient.decide()`, `ToolRegistry`, `AuditLogger` |
| OPA client + policy bundle | `gateway/pdp_client.py`, `policies/rego/agent_policy.rego`, `policies/data/policy_data.json` | Sends PDP input and consumes allow/deny/approval; Rego enforces controls | PEP sends `tool/args/taint/risk/env/ablation` payload to OPA |
| Tools/adapters | `tools/registry.py`, `tools/http.py`, `tools/docs.py`, `tools/tickets.py`, `tools/db.py` | Provides deterministic mock tools and schemas | Invoked only via PEP after policy checks |
| Benchmark harness | `benchmark/runner.py`, `benchmark/scoring.py`, `benchmark/scenarios/scenarios.yaml`, `benchmark/baselines.py` | Replays scenarios across baselines, computes outcomes and metrics | Constructs orchestrator + gateway, writes run and summary JSON |
| Reporting/plots | `scripts/report_results.py`, `benchmark/report.py` | Generates markdown tables and experiment plots | Reads `results/**/summary.json` and `run.json` |
| Audit logging | `agent_runtime/audit.py` and PEP `_audit()` | JSONL event logging per tool decision | Includes tool args, decision, reason, latency, scenario metadata |
| Docs/diagrams | `docs/ARCHITECTURE.md`, `docs/benchmark_methodology.md`, `docs/policy_design.md`, `docs/reproducibility.md` | Explain architecture, methodology, and controls | Mermaid architecture graph in `docs/ARCHITECTURE.md` |
| CI/CD security gate | `.github/workflows/security_eval.yml`, `ci/thresholds.yaml` | Runs benchmark and fails on threshold regressions | Uses `benchmark.runner` outputs + threshold checks |

## Phase 2 - Claims verification matrix

| Claim | Found? | Where | Notes | Risk if missing |
|---|---|---|---|---|
| Tool allowlist and unknown tool denial | Yes | `gateway/pep.py` (`tool_def = self.registry.get(tool)` and `tool_not_registered` path), `tools/registry.py` (`_tools`) | Explicit hard deny before execution | High: arbitrary tool invocation |
| HTTP allowlisted domains and endpoint paths | Yes (B3), partial (B2) | Domain checks in `gateway/pep.py` (B2) and Rego in `policies/rego/agent_policy.rego` (`domain_allowed`, `path_allowed`) | B3 enforces path allowlist; B2 domain-only | High: allowlisted-domain abuse of sensitive paths |
| IP-literal blocking | Partial | `policies/rego/agent_policy.rego` (`is_ip_literal`) | IPv4 literal regex only; no IPv6/private-range semantics | Medium-High: SSRF via alternative address forms |
| Ticket project allowlist and parameter constraints | Partial | Project allowlist in `gateway/pep.py` (B2) + Rego (`ticket_project_not_allowed`), size rule in Rego (`ticket_body_too_large`) | Project + size present; URL/secret-like body constraints claimed in docs are not implemented in current Rego | Medium: exfil in approved channels |
| Canary/secret-like detection and anti-exfil rules | Partial | Canary detection in `agent_runtime/context.py` and deny in Rego (`canary_detected`) | Canary handling exists; generic secret-pattern output policy not found | Medium: non-canary secrets may leak |
| `requires_approval` halting behavior | Yes | `gateway/pep.py` (`ToolCallResult.approval_required`), `agent_runtime/orchestrator.py` (`stopped: approval_required`) | Orchestrator halts on approval-required status | High: silent high-risk action execution |
| Audit includes inputs, decision, reason, correlation IDs | Partial | `gateway/pep.py::_audit`, `agent_runtime/audit.py` | Includes args/decision/reason/scenario/step, but no explicit correlation/request UUID in event schema | Medium: weak traceability across systems |
| Benchmark scenarios + baselines B0-B3 | Yes | `benchmark/scenarios/scenarios.yaml`, `benchmark/baselines.py`, baseline branches in `gateway/pep.py` and `benchmark/runner.py` | Full baseline wiring exists | High: no comparative evidence |
| Scoring (ASR/leakage/task success/FP/latency) | Yes | `benchmark/scoring.py::compute_metrics`, `benchmark/runner.py` outcome mapping | Metrics fields are complete and serialized | Medium: weak empirical defensibility |
| Machine-readable output + plots | Yes | JSON output via `benchmark/report.py::write_json`; reports/plots via `scripts/report_results.py` | Produces summary/run JSON + markdown tables + PNG plots | Low-Medium: weaker communication without artifacts |

## Phase 3 - SSRF and HTTP hardening audit

### Findings

1. Host parsing ambiguity allows credential/userinfo confusion.
- Impacted path: `policies/rego/agent_policy.rego` (`host_from_url`, `parse_url_host`) and `gateway/pep.py` B2 parser.
- Exploit example: `https://api.company.tld:443@evil.tld/status`.
- Why: splitting host on `:` can truncate at first colon and ignore `@evil.tld` tail.
- Severity: High.
- Fix: canonical URL parse, reject userinfo (`@`), enforce normalized host extraction.

2. No private/link-local/reserved range blocking semantics.
- Impacted path: only simple IPv4 literal regex in Rego (`is_ip_literal`).
- Exploit examples: IPv6 literal (`http://[::1]/`), decimal/hex host variants, or DNS names resolving to private IP.
- Severity: High in real-network adapters; currently moderated by `HttpMock` in this repo.
- Fix: explicit IPv4/IPv6 private/link-local checks and, for real adapters, resolve-then-connect pinning.

3. IDN/punycode normalization missing.
- Impacted path: Rego host parsing and B2 domain checks.
- Exploit examples: unicode lookalike domain that bypasses string expectations.
- Severity: Medium.
- Fix: normalize host to ASCII IDNA before allowlist evaluation.

4. Path normalization is string-based, no canonical normalization.
- Impacted path: `parse_url_path` in Rego and runner helper `parse_url_path`.
- Exploit examples: encoded traversal variants (`/%2e%2e/internal`), duplicate slashes.
- Severity: Medium.
- Fix: normalize decoded path before allowlist matching.

5. Redirect handling/proxy bypass not implemented.
- Impacted path: `tools/http.py` is a deterministic mock, no redirect/proxy behavior.
- Status: Not applicable in current mock runtime; would become critical with real HTTP adapter.
- Severity: N/A in current mock; High in productionized adapter.
- Fix: when introducing real HTTP client, disable env proxies and constrain redirects to same allowlisted host/path.

## Phase 4 - Enterprise hireability scorecard (0-10)

| Dimension | Score | Evidence |
|---|---:|---|
| Architecture clarity | 8 | Clear modular split (`agent_runtime/`, `gateway/`, `policies/`, `benchmark/`) and docs in `docs/ARCHITECTURE.md` |
| Code quality/modularity | 7 | Clean separation of PEP/PDP/tool registry; deterministic mocks; some recovery-era drift in tests/init files fixed during review |
| Test quality/coverage | 6 | Good policy behavior tests exist (`tests/test_http_path_policy.py`, `tests/test_approval_semantics.py`), but many integration tests depend on local OPA availability and skip |
| Security posture | 6 | Strong baseline controls in B3; missing robust URL canonicalization/private-IP handling/correlation IDs |
| Documentation/onboarding | 8 | README + methodology + reproducibility + threat docs are strong and thesis-friendly |
| Observability | 6 | JSONL audits and scenario traces exist; correlation chaining and richer audit fields are missing |
| Reproducibility/CI | 7 | CI gate and thresholds present; host dependence on Docker/OPA limits deterministic local verification |
| Product polish/demo/packaging | 7 | CLI/runner/report flow is clear; recruiter-facing narrative and one-shot demo artifacts can be stronger |

## Phase 5 - prioritized backlog

### A) MUST (security/correctness blockers)

1. Harden URL canonicalization for policy checks.
- Description: replace split-based URL parsing with canonical parsing; reject userinfo; normalize host/path; guard IDN.
- Files: `policies/rego/agent_policy.rego`, `gateway/pep.py`, `tests/test_http_path_policy.py`.
- Acceptance criteria: crafted payload `https://api.company.tld:443@evil.tld/status` denied; encoded traversal denied; existing allowlisted paths still allowed.
- Effort: M.
- Dependencies: none.

2. Add explicit private/link-local IP blocking semantics (IPv4 + IPv6 literals).
- Files: `policies/rego/agent_policy.rego`, optionally `gateway/validators.py`, tests.
- Acceptance criteria: `127.0.0.1`, `::1`, `169.254.0.1`, `fe80::1` blocked with clear reason.
- Effort: S-M.
- Dependencies: URL canonicalization.

3. Add correlation ID in audit events and propagate from request context.
- Files: `gateway/pep.py`, `agent_runtime/audit.py`, `agent_runtime/orchestrator.py`, `agent_runtime/main.py`, tests.
- Acceptance criteria: every audit event includes stable `correlation_id` and it appears in API response/tool trace for same run.
- Effort: S.
- Dependencies: none.

### B) SHOULD (hireability boosters)

1. Make policy tests deterministic without mandatory local OPA daemon.
- Description: add local policy-eval test mode (or mock PDP fixture) for core policy paths.
- Files: `tests/*`, optionally `gateway/pdp_client.py` abstraction.
- Acceptance criteria: core tests pass in CI/local without Docker.
- Effort: M.
- Dependencies: none.

2. Upgrade report to include threat table and enterprise-ready summary block.
- Files: `scripts/report_results.py`, docs.
- Acceptance criteria: generated report contains threat breakdown aligned to `scenarios.yaml` `threat` field.
- Effort: S.
- Dependencies: none.

3. Add recruiter-facing README section with measurable outcomes and controls.
- Files: `README.md`, `docs/` assets.
- Acceptance criteria: section explains business/security impact in under 10 bullets with metrics link.
- Effort: S.
- Dependencies: latest benchmark summary available.

### C) NICE (polish)

1. Add architecture one-pager with sequence diagram and trust boundaries.
- Files: `docs/ARCHITECTURE.md` or new `docs/architecture_enterprise.md`.
- Acceptance criteria: includes request flow + trust boundary labels.
- Effort: S.
- Dependencies: none.

2. Add make targets for one-command review artifact bundle.
- Files: `Makefile`.
- Acceptance criteria: one command creates summary table, plots, and markdown executive brief.
- Effort: S.
- Dependencies: reporting script stability.

3. Add changelog discipline for experiment bundles.
- Files: `docs/CHANGELOG_THESIS.md`.
- Acceptance criteria: commit hash, seed list, and key deltas tracked per run.
- Effort: S.
- Dependencies: benchmark run artifacts.
