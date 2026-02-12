package agent.policy

# Returns:
# data.agent.policy.result = { "allow": bool, "requires_approval": bool, "reason": string }

default result = {
  "allow": false,
  "requires_approval": false,
  "reason": "default_deny"
}

# -----------------------
# Helpers
# -----------------------

# Ablation toggles (default to false if ablation not present)
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

tool_allowed if {
  data.data.tools.allowed[_] == input.tool
}

is_ip_literal(host) if {
  regex.match("^[0-9]{1,3}(\\.[0-9]{1,3}){3}$", host)
}

host_from_url(host) = h if {
  parts := split(host, ":")
  h := parts[0]
}

# Parse URL to extract host and path
# Remove scheme by splitting on "://" and taking the second part
parse_url_host(url) = host if {
  scheme_parts := split(url, "://")
  count(scheme_parts) > 1
  after_scheme := scheme_parts[1]
  parts := split(after_scheme, "/")
  host_with_port := parts[0]
  host := host_from_url(host_with_port)
}

parse_url_path(url) = path if {
  scheme_parts := split(url, "://")
  count(scheme_parts) > 1
  after_scheme := scheme_parts[1]
  parts := split(after_scheme, "/")
  count(parts) > 1
  path_with_query := parts[1]
  path_parts := split(path_with_query, "?")
  path := concat("", ["/", path_parts[0]])
} else = "/" if {
  true
}

parsed_host = h if {
  input.tool == "http_get"
  h := parse_url_host(input.args.url)
}

parsed_path = p if {
  input.tool == "http_get"
  p := parse_url_path(input.args.url)
}

domain_allowed_exact(host) if {
  input.env.allowed_domains[_] == host
}

domain_allowed_suffix(host) if {
  d := input.env.allowed_domains[_]
  endswith(host, concat("", [".", d]))
}

domain_allowed(host) if {
  domain_allowed_exact(host)
}

domain_allowed(host) if {
  domain_allowed_suffix(host)
}

# Allowed path list stored in OPA data
allowed_paths_for(host) = paths if {
  paths := data.data.allowed_http_paths[host]
} else = [] if {
  true
}

path_allowed(host, path) if {
  allowed_paths_for(host)[_] == path
}

approval_required_for_tool if {
  data.data.settings.require_approval_for_tools[_] == input.tool
}

approval_required_for_retrieved_risk if {
  input.taint.from_retrieved == true
  data.data.settings.require_approval_when_from_retrieved_for_tool_risk[_] == input.risk.tool_risk
}

ticket_body_too_large if {
  not disable_ticket_size
  input.tool == "create_ticket"
  max := data.data.settings.max_ticket_body_chars
  count(input.args.body) > max
}

# -----------------------
# Deny reasons (priority via else-chain)
# -----------------------

deny_reason := "canary_detected" if {
  not disable_canary
  input.taint.contains_canary == true
} else := "tool_not_allowlisted" if {
  not tool_allowed
} else := "ticket_body_too_large" if {
  ticket_body_too_large
} else := "ip_literal_blocked" if {
  input.tool == "http_get"
  h := parsed_host
  is_ip_literal(h)
} else := "domain_not_allowlisted" if {
  input.tool == "http_get"
  h := parsed_host
  not domain_allowed(h)
} else := "path_not_allowlisted" if {
  not disable_path_allowlist
  input.tool == "http_get"
  h := parsed_host
  path := parsed_path
  not path_allowed(h, path)
} else := "ticket_project_not_allowed" if {
  input.tool == "create_ticket"
  p := input.args.project
  not p in input.env.allowed_ticket_projects
} else := "" if {
  true
}

denied if {
  deny_reason != ""
}

# -----------------------
# Approval (only if not denied)
# -----------------------

needs_approval if {
  not denied
  not disable_approvals
  approval_required_for_tool
}

needs_approval if {
  not denied
  not disable_approvals
  not disable_taint_approvals
  approval_required_for_retrieved_risk
}

# -----------------------
# Allow (only if not denied and no approval needed)
# -----------------------

allowed if {
  not denied
  not needs_approval
}

# -----------------------
# Final result object
# -----------------------

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
  "reason": "approval_required"
} if {
  not denied
  needs_approval
}

result = {
  "allow": true,
  "requires_approval": false,
  "reason": "allowed"
} if {
  allowed
}
