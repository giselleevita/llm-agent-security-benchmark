# Tool Adapters

## Built-in tools
- `search_docs`
- `read_doc`
- `http_get`
- `create_ticket`
- `db_query_readonly`

## Adding a tool
1. Define args model in `tools/registry.py`.
2. Add `ToolDef` mapping and execution function.
3. Add allowlist entry in `policies/data/policy_data.json`.
4. Extend Rego constraints if needed.
5. Add tests for allow/deny/approval behavior.
