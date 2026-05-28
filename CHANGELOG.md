# Changelog

All notable changes to this project are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [1.0.0] — 2026-04-14

### Added
- Secure agent runtime with Tool Gateway (PEP) enforcing least privilege
- OPA-based Policy Decision Point (PDP) with Rego policies
- Benchmark harness for direct injection, indirect injection, tool misuse, data exfiltration, and excessive agency
- Four baselines: B0 (none), B1 (prompt-only), B2 (regex/canary), B3 (policy-enforced gateway)
- CI security gate: benchmark runs on every PR/push and fails on threshold violations
- Audit JSONL trace with correlation IDs for every tool decision
- Taint labeling and approval flow for high-risk actions
- `results/baseline_post_upgrade/` with full comparison across 250 runs
- Mermaid architecture diagram in README
- `SECURITY.md` with responsible disclosure process
- `STRUCTURE_ASSESSMENT.md` (internal design notes)
- `THESIS_ENHANCEMENTS.md` (roadmap extensions)

### Results
- B3 reduces ASR from 54% → 0% and leakage from 12% → 0%
- Task success improves from 48% → 98%
- p95 latency overhead: 8.78ms (acceptable for enterprise agent use)
