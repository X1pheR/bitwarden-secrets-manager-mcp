# Security policy

## Supported versions

Security fixes are applied to the current maintained release line and `main`. Before the first tag, `main` is the only supported development baseline.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability, leaked credential, or secret-handling defect. Use GitHub private vulnerability reporting when available. Otherwise contact the repository owner through the GitHub profile and request a private channel without posting exploit details or secret values publicly.

Use synthetic data in reproduction steps. Never send real Machine Account tokens or production secret values in a report.

## Security boundary

This server is designed so secret values can be used internally for approved operations without becoming model-visible data:

- access tokens are read from private local files;
- secret values never belong in ordinary MCP tool arguments;
- secret values and notes are excluded from MCP responses;
- protected secret create/update imports accept only private regular files under configured input directories;
- delivery targets are constrained to configured output directories and replaced atomically;
- administrative secret/project capabilities are disabled by default per profile;
- deletes are single-resource operations with exact expected metadata and explicit confirmation;
- provider exceptions are replaced with bounded error messages rather than echoing upstream content;
- normal server logs and CI do not print access tokens or secret values;
- there is no generic SDK passthrough, plaintext secret reveal, arbitrary command execution, secret-injected process execution, or bulk destructive operation.

Bitwarden Machine Account permissions remain the underlying provider authorization boundary. The configured `expected_project_names` check adds a fail-closed application boundary: the full project set visible to a profile must match exactly before scoped operations proceed.

## Dependency and code security

The repository pins the Bitwarden SDK version used by the maintained product, locks Python dependencies, verifies source and package behavior in CI, and uses Dependabot. Public-release acceptance additionally reviews applicable GitHub-native dependency alerts, secret scanning/push protection, CodeQL results, repository history, and release immutability.
