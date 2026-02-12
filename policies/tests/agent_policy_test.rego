package agent.policy_test

base_input := {
  "tool": "read_doc",
  "args": {"doc_id": "refund_policy"},
  "taint": {"from_user": true, "from_retrieved": false, "contains_canary": false},
  "risk": {"tool_risk": "read", "high_risk_action": false, "risk_score": 0.2},
  "env": {"allowed_domains": ["api.company.tld", "docs.company.tld"], "allowed_ticket_projects": ["SEC", "IT"]},
  "ablation": {}
}

test_deny_unknown_tool if {
  req := object.union(base_input, {"tool": "delete_user"})
  result := data.agent.policy.result with input as req
  result.allow == false
  result.reason == "DENY_TOOL_NOT_ALLOWLISTED"
}

test_requires_approval_for_create_ticket if {
  req := object.union(base_input, {
    "tool": "create_ticket",
    "args": {"project": "SEC", "title": "x", "body": "ok"},
    "risk": {"tool_risk": "action", "high_risk_action": true, "risk_score": 0.9}
  })
  result := data.agent.policy.result with input as req
  result.requires_approval == true
  result.reason == "APPROVAL_REQUIRED"
}

test_allow_valid_http_get if {
  req := object.union(base_input, {
    "tool": "http_get",
    "args": {"url": "https://api.company.tld/status"},
    "risk": {"tool_risk": "network", "high_risk_action": true, "risk_score": 0.85}
  })
  result := data.agent.policy.result with input as req
  result.allow == true
  result.reason == "ALLOWED"
}

test_requires_approval_for_retrieved_network if {
  req := object.union(base_input, {
    "tool": "http_get",
    "args": {"url": "https://api.company.tld/status"},
    "taint": {"from_user": false, "from_retrieved": true, "contains_canary": false},
    "risk": {"tool_risk": "network", "high_risk_action": true, "risk_score": 0.95}
  })
  result := data.agent.policy.result with input as req
  result.requires_approval == true
  result.reason == "APPROVAL_REQUIRED"
}
