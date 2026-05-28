# Contributing

Thank you for your interest in contributing to `llm-agent-security-benchmark`.

## Getting started

1. Fork the repository and create a branch from `main`.
2. Install dependencies:
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -e .
   ```
3. Run the tests before making changes:
   ```bash
   pytest tests/
   ```

## Branch naming

| Type | Pattern | Example |
|---|---|---|
| Feature | `feat/description` | `feat/add-indirect-injection-scenario` |
| Bug fix | `fix/description` | `fix/opa-client-timeout` |
| Docs | `docs/description` | `docs/update-architecture` |
| Refactor | `refactor/description` | `refactor/gateway-validators` |

## Issue labels

- `bug` — something is broken
- `enhancement` — new feature or scenario
- `docs` — documentation gap
- `benchmark` — new or updated evaluation scenario
- `policy` — OPA policy update
- `ci` — CI/CD related change

## Pull request checklist

- [ ] Tests pass (`pytest tests/`)
- [ ] New scenarios include expected metrics in the scenario YAML
- [ ] New policies include a test case in `tests/`
- [ ] README updated if behavior changes
- [ ] No secrets or real credentials committed

## Security issues

Please report security vulnerabilities via the process described in `SECURITY.md`. Do not open public issues for security bugs.

## Code style

This project uses `ruff` for linting. Run before committing:
```bash
ruff check .
```
