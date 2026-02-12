# Policy Authoring Guide

## Layout
- `policies/rego/agent_policy.rego`: final decision object.
- `policies/rego/tool_allowlist.rego`: allowlist predicates.
- `policies/rego/param_constraints.rego`: URL/project/path constraints.
- `policies/rego/data_boundaries.rego`: canary/data boundary checks.
- `policies/rego/approvals.rego`: approval rules.

## Reason Codes
Use uppercase stable reason codes:
- `DENY_*`
- `APPROVAL_REQUIRED`
- `ALLOWED`

## Testing
Run:
```bash
make policy-test
```
Add regression tests in `policies/tests/*.rego` for every new rule path.
