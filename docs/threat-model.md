# Threat Model

## Assets
- Integrity of tool execution (no unauthorized actions)
- Confidentiality (no canary token leakage)
- Availability (agent does not spiral into uncontrolled tool loops)
- Auditability (every decision is explainable and reproducible)

## Attacker capabilities
- Controls user prompts (direct prompt injection)
- Can inject malicious instructions into retrieved documents (indirect injection)
- Tries to force tool misuse (domain/path/project abuse)
- Attempts data exfiltration via tool payloads and final output

## In-scope
- Direct and indirect prompt injection
- Unauthorized tool invocation
- Parameter abuse (domains, paths, projects, payload sizes)
- Excessive agency (high-risk actions without approval)
- Leakage of synthetic canary tokens

## Out-of-scope
- Training-time attacks / model poisoning
- Malware/exploit development
- Real production secrets or personal data
- Side-channel attacks on infrastructure outside this repo

## Security assumptions
- The gateway and OPA run in a trusted environment
- Tools are deterministic mocks (no real external integration)
- Canary tokens represent sensitive data markers (no real secrets used)

## Ethical safeguards
- No real secrets or personal data
- No real network calls
- Scenario suite is defensive and used to validate mitigations
- Results are reproducible and do not enable operational exploitation
