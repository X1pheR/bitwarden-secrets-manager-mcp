# Bitwarden Secrets Manager MCP

A typed, value-blind [Model Context Protocol](https://modelcontextprotocol.io/) server for **Bitwarden Secrets Manager** built on the official Bitwarden Secrets Manager Python SDK.

> **Scope:** this project manages Bitwarden Secrets Manager projects and secrets. It **does not manage Bitwarden Password Manager vaults, items, collections, or passwords**.

This is a community project and is not affiliated with or endorsed by Bitwarden.

## Why this server

The server gives MCP clients useful Bitwarden Secrets Manager administration without turning secret values into model-visible data. It supports metadata discovery, controlled server-side file delivery, protected-file secret mutation, and guarded project administration through typed tools.

The provider implementation uses one path only: `bitwarden-sdk`. There is no generic provider command passthrough and no arbitrary process execution with injected secrets.

## Security model

Secret values may exist briefly inside the server when Bitwarden returns them for approved delivery or when a protected source file is used for create/update. They are deliberately excluded from:

- MCP tool responses;
- ordinary MCP tool arguments;
- server diagnostics and normal logs;
- repository examples and CI configuration.

Secret create/update reads values only from private regular files inside per-profile allowlisted input directories. File and env delivery writes only below allowlisted output directories. Administrative secret and project capabilities are profile-specific and disabled by default. Delete tools additionally require exact expected metadata and `confirm=true`.

There is no plaintext secret-value retrieval tool, generic SDK passthrough, arbitrary command runner, or bulk delete tool.

## Requirements

- Python 3.12 or newer
- a Bitwarden Secrets Manager Machine Account access token with only the projects/permissions the profile should expose
- a private local token file (`0600`)

## Installation

Install the package and its declared Python dependencies in one step:

```bash
uv tool install bitwarden-secrets-manager-mcp
```

or, after a release, directly from an immutable GitHub release wheel:

```bash
uv tool install "https://github.com/X1pheR/bitwarden-secrets-manager-mcp/releases/download/v0.1.0/bitwarden_secrets_manager_mcp-0.1.0-py3-none-any.whl"
```

A separate native Bitwarden command-line program is not required. The official Python SDK is installed as a package dependency.

## Configuration

Set `BITWARDEN_SM_PROFILES_FILE` to an absolute JSON file path. Each profile defines one Machine Account boundary, organization, endpoint set, exact expected project names, file allowlists, and administrative capabilities.

```json
{
  "profiles": {
    "example": {
      "access_token_file": "/run/secrets/bitwarden-sm-token",
      "organization_id": "00000000-0000-4000-8000-000000000001",
      "environment": "eu",
      "expected_project_names": ["Example Runtime"],
      "allowed_input_directories": ["/srv/secure/import"],
      "allowed_output_directories": ["/srv/runtime/secrets"],
      "allow_secret_create": false,
      "allow_secret_update": false,
      "allow_secret_delete": false,
      "allow_project_create": false,
      "allow_project_update": false,
      "allow_project_delete": false
    }
  }
}
```

`environment` accepts `us`, `eu`, or `custom`. Cloud profiles use Bitwarden's standard API and identity endpoints. A `custom` profile must explicitly provide both `api_url` and `identity_url`, which supports self-hosted deployments accepted by the current SDK configuration contract.

Optional `BITWARDEN_SM_DEFAULT_FILE_MODE` controls the mode for newly delivered files and defaults to `0600`. Existing target files keep their current ownership and mode during atomic replacement.

See [`examples/profiles.example.json`](examples/profiles.example.json) and [`examples/mcp.example.json`](examples/mcp.example.json).

## MCP tools

The public surface includes status/capability discovery, project metadata, secret metadata, value-blind file/env delivery, protected-file secret create/update, exact secret delete, and guarded project create/update/delete.

See [`docs/tools.md`](docs/tools.md) for the complete tool contract and capability flags.

## Development

```bash
./scripts/verify.sh
```

The verification script performs a locked dependency sync, compilation, the full test suite, source security checks, package builds, and a fresh wheel installation/import check.

## Upstream relationship

The Bitwarden integration uses the official [`bitwarden-sdk`](https://pypi.org/project/bitwarden-sdk/) package from Bitwarden's [`sdk-sm`](https://github.com/bitwarden/sdk-sm) project. This repository only defines the bounded MCP product layer around that SDK.

## License

MIT. See [`LICENSE`](LICENSE).
