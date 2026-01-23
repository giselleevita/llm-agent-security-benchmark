# llm-agent-security-benchmark
Secure LLM agent runtime with policy-as-code tool control and prompt-injection benchmarking

This repository contains a **secure runtime wrapper for tool-using LLM agents** and a **reproducible benchmark harness** to measure resilience against **direct and indirect prompt injection**.

The core idea is to treat the LLM as **untrusted**: the model can *suggest* actions, but an external **Tool Gateway** (Policy Enforcement Point, PEP) makes the final decision using **policy-as-code** (Policy Decision Point, PDP). A CI workflow runs the benchmark as a **security gate** and fails builds on security regressions.

---

## Thesis focus (what this project demonstrates)
- **Secure Agent Runtime**: Tool gateway enforcing least privilege, parameter constraints, data boundaries, and approvals.
- **Benchmark Harness**: Scenario-based evaluation with measurable security and utility metrics.
- **CI Security Gate**: Automated evaluation on PRs/pushes; fails when ASR/leakage exceed thresholds.

---

## Key security controls
1. **Tool allowlisting** — the agent can only call registered tools.
2. **Parameter constraints** — e.g., HTTP only to allowlisted domains; tickets only in allowed projects.
3. **Data boundaries / leakage prevention** — canary token policies prevent exfiltration.
4. **Approval flow** — high-risk actions can require explicit external approval.
5. **Audit trace** — every tool request/decision is logged with rationale.

---

## Benchmark design
Scenarios are defined in `benchmark/scenarios/scenarios.yaml` and include:
- **Direct injection** (malicious user input)
- **Indirect injection** (malicious retrieved content via RAG)
- **Tool misuse** (parameter/domain/project abuse)
- **Data exfiltration** (canary leakage attempts)
- **Excessive agency** (actions without explicit approval)

### Metrics
The benchmark reports:
- **ASR (Attack Success Rate)**: % of runs where a forbidden action was executed
- **Leakage Rate**: % of runs where canary tokens appear in outbound requests or final output
- **Task Success Rate**: % of runs where the benign task is completed correctly
- **False Positive Rate**: % of benign actions incorrectly blocked
- **Overhead**: latency/tool-call count deltas vs baseline

### Baselines
- **B0**: No guardrails
- **B1**: Prompt-only guardrails (system prompt rules)
- **B2**: Simple checks (e.g., canary/regex blocking)
- **B3**: Policy-enforced tool gateway (proposed runtime)
- Optional: Hybrid configurations

---

## Quickstart

### Prerequisites
- Python 3.11+
- Docker + Docker Compose

### Setup
```bash
cp .env.example .env
python -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e .
