## Security Policy

This repository contains a **secure agent runtime** and a **prompt-injection benchmark harness**. It is designed for **research and evaluation** of security controls for tool-using LLM agents, not as a drop-in production security gateway.

### Scope

In scope:

- Evaluating **policy-enforced tool use** (tool allowlists, parameter constraints, approvals).
- Measuring resilience to **direct and indirect prompt injection**, tool misuse, and data exfiltration attempts.
- Running a **security evaluation gate in CI** that fails builds when metrics violate configured thresholds.

Out of scope:

- End-to-end hardening of the surrounding LLM stack (model hosting, auth, network perimeter).
- Protection against compromised tool backends, model supply-chain issues, or malicious infrastructure.
- Guarantees that the included scenarios cover all real-world attack techniques.

### Intended usage

- As a **benchmarking framework** to compare agent security controls and configurations.
- As a **reference architecture** for policy-first agent runtimes (PEP/PDP style), where decisions are auditable.
- As a **CI security check** that turns evaluation metrics into operational gates.

If you adapt this runtime for production:

- Perform a dedicated **threat model** for your environment and tools.
- Add **monitoring, alerting, and rate-limiting** around any automated blocking decisions.
- Validate thresholds and scenarios against **your own attack library and datasets**.

### Reporting vulnerabilities

If you believe you have found a vulnerability in:

- The enforcement logic (e.g., a bypass of the gateway/policies in supported scenarios), or
- The benchmark/CI integration (e.g., a way to tamper with evaluation results),

please open a **private issue** or contact the maintainer directly via GitHub instead of disclosing it publicly first. Include:

- A minimal reproducible example (scenario, configuration, and observed behavior).
- Environment details (Python version, OS, how you ran the benchmark or runtime).

Security-impacting reports will be prioritized where possible, subject to the research nature of the project.

