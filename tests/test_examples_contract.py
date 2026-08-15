import json
from pathlib import Path

ROOT = Path(__file__).parents[1]


def test_profile_example_uses_new_typed_endpoint_and_capability_contract() -> None:
    data = json.loads((ROOT / "examples" / "profiles.example.json").read_text(encoding="utf-8"))
    profile = data["profiles"]["example"]
    assert profile["environment"] == "eu"
    assert "organization_id" in profile
    assert "access_token_file" in profile
    assert all(profile[name] is False for name in (
        "allow_secret_create", "allow_secret_update", "allow_secret_delete",
        "allow_project_create", "allow_project_update", "allow_project_delete",
    ))
    assert "server_url" not in profile


def test_mcp_example_uses_only_new_executable_and_config_env() -> None:
    data = json.loads((ROOT / "examples" / "mcp.example.json").read_text(encoding="utf-8"))
    server = data["mcpServers"]["bitwarden-secrets-manager"]
    assert server["command"] == "bitwarden-secrets-manager-mcp"
    assert set(server["env"]) == {"BITWARDEN_SM_PROFILES_FILE"}
