# Security Claims

Each claim maps to concrete controls and test/benchmark evidence.

| Claim | Primary Control | Test Evidence | Scenario Evidence |
|---|---|---|---|
| Unknown tools are denied | `is_tool_allowlisted` in `policies/rego/tool_allowlist.rego` | `policies/tests/agent_policy_test.rego::test_deny_unknown_tool` | `DI-04`, `DI-06` |
| IP literals and private ranges are denied | `http_ip_literal_blocked`, `http_private_ip_blocked` in `policies/rego/param_constraints.rego` | `policies/tests/http_constraints_test.rego::test_deny_ip_literal` | `TM-21` and malicious URL cases |
| Metadata endpoints are denied | `http_metadata_endpoint_blocked` in `policies/rego/param_constraints.rego` | `policies/tests/http_constraints_test.rego::test_deny_metadata_endpoint_name` | indirect/tool-misuse scenarios using external fetch |
| URL userinfo/authority tricks are denied | `http_invalid_authority` | `policies/tests/http_constraints_test.rego::test_deny_userinfo_authority` | regression in `tests/test_http_path_policy.py` |
| Traversal encodings are denied | `http_path_traversal` and path allowlist checks | `policies/tests/http_constraints_test.rego::test_deny_path_traversal_encoded` | `TM-*` HTTP misuse scenarios |
| Punycode/unicode host bypass is denied | `http_punycode_host`, `http_non_ascii_host` | `policies/tests/http_constraints_test.rego::test_deny_punycode_host`, `test_deny_unicode_host` | malicious domain scenarios |
| Unsafe redirects are blocked | Policy deny `DENY_UNSAFE_REDIRECT` (`input.args.follow_redirects`) + `HttpReal` redirect checks | `policies/tests/http_constraints_test.rego::test_deny_unsafe_redirect_flag`, `tests/test_http_adapter_security.py::test_blocks_redirect_when_disabled` | adapter-level regression corpus |
| Proxy env bypass is prevented in real adapter mode | `httpx.Client(..., trust_env=False)` in `tools/http_real.py` | `tests/test_http_adapter_security.py::test_ignores_proxy_env` | adapter-level regression corpus |
| High-risk actions require approval | `needs_approval` in `policies/rego/approvals.rego` | `policies/tests/agent_policy_test.rego::test_requires_approval_for_create_ticket` | `DI-05`, `II-20`, `EA-*` |
| Retrieved-content network actions require approval | `approval_required_for_retrieved_risk` | `policies/tests/agent_policy_test.rego::test_requires_approval_for_retrieved_network` | `II-*` |
| Canary leakage is blocked | `contains_canary` in `policies/rego/data_boundaries.rego` | `tests/test_gateway_policy_enforcement.py::test_b3_blocks_canary_leakage_in_ticket` | `DI-03`, `II-11`, `EX-*` |
| Decisions are auditable with correlation context | audit event schema in `gateway/pep.py` + `agent_runtime/audit.py` | `tests/test_audit_correlation.py` | all benchmark runs (JSONL trace) |

## Non-claims
- The repository does not claim complete production network security by default because benchmark mode uses mock tools.
- The repository does not claim protection against training-time model compromise.
