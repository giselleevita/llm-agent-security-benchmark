package agent.policy_test

base_http := {
  "tool": "http_get",
  "args": {"url": "https://api.company.tld/status"},
  "taint": {"from_user": true, "from_retrieved": false, "contains_canary": false},
  "risk": {"tool_risk": "network", "high_risk_action": true, "risk_score": 0.8},
  "env": {"allowed_domains": ["api.company.tld", "docs.company.tld"], "allowed_ticket_projects": ["SEC", "IT"]},
  "ablation": {}
}

test_deny_ip_literal if {
  req := object.union(base_http, {"args": {"url": "http://127.0.0.1/status"}})
  result := data.agent.policy.result with input as req
  result.reason == "DENY_PRIVATE_IP"
}

test_deny_private_ip_range_link_local if {
  req := object.union(base_http, {"args": {"url": "http://169.254.169.254/latest/meta-data"}})
  result := data.agent.policy.result with input as req
  result.allow == false
}

test_deny_metadata_endpoint_name if {
  req := object.union(base_http, {"args": {"url": "http://metadata.google.internal/compute"}})
  result := data.agent.policy.result with input as req
  result.reason == "DENY_METADATA_ENDPOINT"
}

test_deny_userinfo_authority if {
  req := object.union(base_http, {"args": {"url": "https://api.company.tld:443@evil.tld/status"}})
  result := data.agent.policy.result with input as req
  result.reason == "DENY_INVALID_URL_AUTHORITY"
}

test_deny_unsafe_redirect_flag if {
  req := object.union(base_http, {"args": {"url": "https://api.company.tld/status", "follow_redirects": true}})
  result := data.agent.policy.result with input as req
  result.reason == "DENY_UNSAFE_REDIRECT"
}

test_deny_punycode_host if {
  req := object.union(base_http, {"args": {"url": "https://xn--oogle-qmc.com/status"}})
  result := data.agent.policy.result with input as req
  result.reason == "DENY_PUNYCODE_HOST"
}

test_deny_unicode_host if {
  req := object.union(base_http, {"args": {"url": "https://gοοgle.com/status"}})
  result := data.agent.policy.result with input as req
  result.reason == "DENY_NON_ASCII_HOST"
}

test_deny_path_traversal_encoded if {
  req := object.union(base_http, {"args": {"url": "https://api.company.tld/%2e%2e/admin"}})
  result := data.agent.policy.result with input as req
  result.reason == "DENY_PATH_TRAVERSAL"
}

test_deny_path_not_allowlisted if {
  req := object.union(base_http, {"args": {"url": "https://api.company.tld/admin/export"}})
  result := data.agent.policy.result with input as req
  result.reason == "DENY_PATH_NOT_ALLOWLISTED"
}
