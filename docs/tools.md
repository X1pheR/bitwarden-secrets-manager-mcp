# Tool reference

All tools operate on **Bitwarden Secrets Manager** only. Secret values are never returned through MCP. Tools use typed schemas; unknown fields are rejected.

## Profile and discovery tools

### `bitwarden_status`

Checks authenticated SDK access, exact expected project scope, endpoint configuration, file allowlists, and effective capability flags. Omit `profile` to check every configured profile.

### `bitwarden_project_list`

Lists project metadata after exact scope verification. Omit `profile` to aggregate configured profiles.

### `bitwarden_project_get`

Returns metadata for one project ID only after proving that ID is inside the profile's exact scope.

### `bitwarden_secret_list`

Lists secret identifiers/keys and project IDs. Optional `project_id` and key-text `query` filters are metadata-only.

### `bitwarden_secret_get`

Resolves an exact UUID or unambiguous exact key and returns metadata only. The secret value and note are not returned.

## Value-blind delivery tools

### `bitwarden_secret_write_file`

Resolves one secret internally and atomically writes its UTF-8 value to `target_path`. The target must be below an approved output directory. Existing regular files keep ownership and mode; new files use `BITWARDEN_SM_DEFAULT_FILE_MODE`.

### `bitwarden_secret_write_env_file`

Resolves a mapping of environment variable names to secret identifiers and atomically replaces one complete raw `KEY=value` file. Secret values containing CR/LF or NUL are rejected because raw dotenv encoding would be ambiguous.

## Secret administration

These profile capabilities are **disabled by default**:

- `allow_secret_create`
- `allow_secret_update`
- `allow_secret_delete`

### `bitwarden_secret_create_from_file`

Creates exactly one secret. Arguments contain `profile`, `project_id`, `key`, and `source_path`; the secret value is read only from the private allowlisted server-side source file.

### `bitwarden_secret_update_from_file`

Updates exactly one secret's value from a private allowlisted source file. The current key, note, and project association are preserved internally and are not exposed as secret-value inputs.

### `bitwarden_secret_delete`

Deletes exactly one scoped secret. Requires `project_id`, an exact UUID or key `identifier`, matching `expected_key`, and `confirm=true`.

## Project administration

These profile capabilities are **disabled by default**:

- `allow_project_create`
- `allow_project_update`
- `allow_project_delete`

### `bitwarden_project_create`

Creates one project after the current profile project set exactly matches `expected_project_names`. Because creation changes that set, operators should update the profile's expected scope before subsequent scoped calls when the new project is intended to remain accessible.

### `bitwarden_project_update`

Renames one project only when the project ID is currently inside the exact configured scope. A rename changes the observed name set, so update `expected_project_names` accordingly after the operation.

### `bitwarden_project_delete`

Deletes exactly one project already inside the exact configured scope. Requires matching `expected_name` and `confirm=true`. Deleting a project may also affect secrets according to Bitwarden's provider semantics; keep this capability off unless the operational consequence is understood.

## Endpoint configuration

`environment` supports:

- `us` → Bitwarden US cloud API and identity endpoints;
- `eu` → Bitwarden EU cloud API and identity endpoints;
- `custom` → explicit `api_url` plus `identity_url` for self-hosted/custom SDK endpoints.

A cloud environment rejects custom URL overrides so endpoint intent stays typed and unambiguous.
