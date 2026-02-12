# Scenarios

Scenario definitions live in `benchmark/scenarios/scenarios.yaml`.

## Categories/Threats
- `direct_injection`
- `indirect_injection`
- `tool_misuse`
- `exfiltration`
- `excessive_agency`

## Add a New Scenario
1. Add a new object under `scenarios` with unique `id`.
2. Set `category` and `threat`.
3. Add expected constraints under `expected`.
4. Run: `make bench`.
5. Verify summary/report outputs and claim mappings.
