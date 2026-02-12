package agent.policy

is_ip_literal(host) if {
  regex.match("^[0-9]{1,3}(\\.[0-9]{1,3}){3}$", host)
}

private_ipv4(host) if {
  regex.match("^10\\.", host)
}

private_ipv4(host) if {
  regex.match("^127\\.", host)
}

private_ipv4(host) if {
  regex.match("^169\\.254\\.", host)
}

private_ipv4(host) if {
  regex.match("^172\\.(1[6-9]|2[0-9]|3[0-1])\\.", host)
}

private_ipv4(host) if {
  regex.match("^192\\.168\\.", host)
}

private_ipv4(host) if {
  regex.match("^0\\.", host)
}

is_ipv6_literal(host) if {
  contains(host, ":")
}

url_authority(url) = authority if {
  scheme_parts := split(url, "://")
  count(scheme_parts) > 1
  after_scheme := scheme_parts[1]
  parts := split(after_scheme, "/")
  authority := parts[0]
} else = authority if {
  parts := split(url, "/")
  authority := parts[0]
}

host_from_authority(authority) = host if {
  startswith(authority, "[")
  parts := split(authority, "]")
  host := trim(parts[0], "[]")
} else = host if {
  contains(authority, "@")
  parts := split(authority, "@")
  tail := parts[count(parts)-1]
  port_parts := split(tail, ":")
  host := port_parts[0]
} else = host if {
  port_parts := split(authority, ":")
  host := port_parts[0]
}

parse_url_host(url) = host if {
  authority := url_authority(url)
  host := lower(host_from_authority(authority))
}

contains_userinfo(url) if {
  authority := url_authority(url)
  contains(authority, "@")
}

host_is_ascii(host) if {
  regex.match("^[a-z0-9.-]+$", host)
}

parse_url_path(url) = path if {
  scheme_parts := split(url, "://")
  count(scheme_parts) > 1
  after_scheme := scheme_parts[1]
  parts := split(after_scheme, "/")
  count(parts) > 1
  path_with_query := concat("/", array.slice(parts, 1, count(parts)))
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

allowed_paths_for(host) = paths if {
  paths := data.data.allowed_http_paths[host]
} else = [] if {
  true
}

path_allowed(host, path) if {
  allowed_paths_for(host)[_] == path
}

url_contains_encoded_traversal(url) if {
  lower_url := lower(url)
  contains(lower_url, "%2e%2e")
}

path_contains_traversal(path) if {
  contains(path, "/../")
}

path_contains_traversal(path) if {
  endswith(path, "/..")
}

http_invalid_authority if {
  input.tool == "http_get"
  contains_userinfo(input.args.url)
}

http_unsafe_redirect_flag if {
  input.tool == "http_get"
  input.args.follow_redirects == true
}

http_non_ascii_host if {
  input.tool == "http_get"
  h := parsed_host
  not host_is_ascii(h)
}

http_punycode_host if {
  input.tool == "http_get"
  h := parsed_host
  contains(h, "xn--")
}

http_private_ip_blocked if {
  input.tool == "http_get"
  h := parsed_host
  private_ipv4(h)
}

http_ipv6_literal_blocked if {
  input.tool == "http_get"
  h := parsed_host
  is_ipv6_literal(h)
}

http_ip_literal_blocked if {
  input.tool == "http_get"
  h := parsed_host
  is_ip_literal(h)
}

http_metadata_endpoint_blocked if {
  input.tool == "http_get"
  h := parsed_host
  h == "169.254.169.254"
}

http_metadata_endpoint_blocked if {
  input.tool == "http_get"
  h := parsed_host
  data.data.settings.blocked_metadata_hosts[_] == h
}

http_domain_not_allowlisted if {
  input.tool == "http_get"
  h := parsed_host
  not domain_allowed(h)
}

http_path_traversal if {
  input.tool == "http_get"
  url_contains_encoded_traversal(input.args.url)
}

http_path_traversal if {
  input.tool == "http_get"
  p := parsed_path
  path_contains_traversal(p)
}

http_path_not_allowlisted if {
  input.tool == "http_get"
  not disable_path_allowlist
  h := parsed_host
  p := parsed_path
  not path_allowed(h, p)
}

ticket_project_not_allowed if {
  input.tool == "create_ticket"
  p := input.args.project
  not p in input.env.allowed_ticket_projects
}

ticket_body_too_large if {
  not disable_ticket_size
  input.tool == "create_ticket"
  max := data.data.settings.max_ticket_body_chars
  count(input.args.body) > max
}
