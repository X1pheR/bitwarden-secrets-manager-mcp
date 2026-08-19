# Contributing

Contributions are welcome through GitHub issues and pull requests.

## Before opening a change

- Use GitHub Issues for reproducible bugs and feature proposals.
- Use the private reporting process in [SECURITY.md](SECURITY.md) for suspected vulnerabilities or secret-handling defects.
- Keep a pull request focused on one coherent change and avoid unrelated formatting or dependency churn.
- Never include real Bitwarden Machine Account tokens, production secret values, private endpoints, or other credentials in issues, fixtures, tests, logs, or commits.

## Development setup

Use Python 3.12 and the committed lock file:

```bash
./scripts/verify.sh
```

The verification entry point performs the locked dependency sync, compilation, tests, source security checks, package builds, and a fresh wheel installation/import check.

## Change requirements

- Add or update automated tests for new behavior and bug fixes where a regression test is practical.
- Preserve the value-blind MCP boundary; do not add plaintext secret retrieval, generic SDK passthrough, arbitrary command execution, or secret values in normal MCP arguments/responses.
- Update `docs/tools.md` when a tool, capability flag, mutation classification, guard, permission requirement, or externally visible contract changes.
- Update README or security documentation when requirements, compatibility, configuration, or trust boundaries change.
- Add a concise entry under `Unreleased` in [CHANGELOG.md](CHANGELOG.md) for user-visible changes.
- Keep dependency changes within declared compatibility bounds unless the pull request explicitly owns a compatibility change.

A pull request is ready for review when `./scripts/verify.sh` passes and its documentation describes the behavior it changes.
