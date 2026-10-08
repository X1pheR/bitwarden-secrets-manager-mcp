# Changelog

This file records user-visible changes to `bitwarden-secrets-manager-mcp`. Security fixes with a public CVE or equivalent identifier are called out explicitly in the release that fixes them.

## Unreleased

## 0.2.0 - 2026-09-05

- Added value-blind cryptographically secure generated-secret creation with Bitwarden-like password policy controls.
- Added public OpenSSF Scorecard reporting and protected-branch repository controls.
- Release artifacts now include signed GitHub/Sigstore build provenance alongside checksums and reproducible package artifacts.
- Added explicit contribution and private vulnerability-reporting routes.

## 0.1.0 - 2026-08-16

Initial public release.

- Added 13 typed, value-blind MCP tools for Bitwarden Secrets Manager profile/status discovery, project/secret metadata, bounded file/env delivery, protected-file secret mutation, guarded secret deletion and default-off project administration.
- Used the official `bitwarden-sdk` Python package as the only Bitwarden runtime client path.
- Kept Machine Account tokens and secret values outside ordinary MCP tool arguments and responses, with private file allowlists for import/delivery operations.
- Published reproducible wheel/source artifacts with `SHA256SUMS` and established the `bitwarden-sdk==2.1.0` compatibility baseline.
