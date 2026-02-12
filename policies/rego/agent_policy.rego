package agent.policy

# Returns:
# data.agent.policy.result = { "allow": bool, "requires_approval": bool, "reason": string }

default result = {
  "allow": false,
  "requires_approval": false,
  "reason": "DENY_DEFAULT"
}

# Ablation toggles (default false when absent)
disable_canary if {
  input.ablation.disable_canary
}

disable_path_allowlist if {
  input.ablation.disable_path_allowlist
}

disable_approvals if {
  input.ablation.disable_approvals
}

disable_taint_approvals if {
  input.ablation.disable_taint_approvals
}

disable_ticket_size if {
  input.ablation.disable_ticket_size
}

deny_reason := "DENY_CANARY_DETECTED" if {
  contains_canary
} else := "DENY_TOOL_NOT_ALLOWLISTED" if {
  not is_tool_allowlisted
} else := "DENY_TICKET_BODY_TOO_LARGE" if {
  ticket_body_too_large
} else := "DENY_PRIVATE_IP" if {
  http_private_ip_blocked
} else := "DENY_IPV6_LITERAL" if {
  http_ipv6_literal_blocked
} else := "DENY_IP_LITERAL" if {
  http_ip_literal_blocked
} else := "DENY_METADATA_ENDPOINT" if {
  http_metadata_endpoint_blocked
} else := "DENY_INVALID_URL_AUTHORITY" if {
  http_invalid_authority
} else := "DENY_UNSAFE_REDIRECT" if {
  http_unsafe_redirect_flag
} else := "DENY_NON_ASCII_HOST" if {
  http_non_ascii_host
} else := "DENY_PUNYCODE_HOST" if {
  http_punycode_host
} else := "DENY_DOMAIN_NOT_ALLOWLISTED" if {
  http_domain_not_allowlisted
} else := "DENY_PATH_TRAVERSAL" if {
  http_path_traversal
} else := "DENY_PATH_NOT_ALLOWLISTED" if {
  http_path_not_allowlisted
} else := "DENY_TICKET_PROJECT_NOT_ALLOWED" if {
  ticket_project_not_allowed
} else := "" if {
  true
}

denied if {
  deny_reason != ""
}

allowed if {
  not denied
  not needs_approval
}

result = {
  "allow": false,
  "requires_approval": false,
  "reason": deny_reason
} if {
  denied
}

result = {
  "allow": false,
  "requires_approval": true,
  "reason": "APPROVAL_REQUIRED"
} if {
  not denied
  needs_approval
}

result = {
  "allow": true,
  "requires_approval": false,
  "reason": "ALLOWED"
} if {
  allowed
}
