# Policy Design (OPA / Rego)

## Policy output contract
OPA returns `data.agent.policy.result`:
```json
{ "allow": false, "requires_approval": true, "reason": "approval_required" }
```

## Key rules

- **Tool allowlist**: only registered tools can execute
- **Canary blocking**: if canary detected in outbound payload -> deny
- **HTTP domain allowlist**: only approved domains
- **HTTP endpoint allowlist**: only approved URL paths per domain (B3-only)
- **Ticket project allowlist**: only approved projects
- **Ticket size guardrail**: deny oversized ticket bodies (B3-only)
- **Taint-aware approvals**: if input is derived from retrieved content AND tool risk is network/action -> require approval

## Why endpoint allowlisting matters

Domain allowlists alone are insufficient. Attacks often remain within allowed domains but hit sensitive endpoints (`/admin/export`, `/internal/secrets`). Exact path allowlisting mitigates that class of attacks.

## Why approvals matter

Approvals block excessive agency and allow human review for high-risk actions, especially when triggered by indirect prompt injection.
