from pathlib import Path

ROOT = Path(__file__).parents[1]
README = (ROOT / "README.md").read_text(encoding="utf-8")
TOOLS = (ROOT / "docs" / "tools.md").read_text(encoding="utf-8")
SECURITY = (ROOT / "SECURITY.md").read_text(encoding="utf-8")


def test_readme_names_product_sdk_and_password_manager_boundary() -> None:
    assert "Bitwarden Secrets Manager MCP" in README
    assert "official Bitwarden Secrets Manager Python SDK" in README
    assert "Password Manager" in README
    assert "does not" in README.lower()
    assert "value-blind" in README.lower()
    assert "Bitwarden Secrets Manager" in README


def test_readme_installation_has_no_separate_native_cli_prerequisite() -> None:
    install = README.split("## Installation", 1)[1].split("##", 1)[0]
    assert "pipx install" in install or "uv tool install" in install
    assert "separate" not in install.lower() or "not" in install.lower()


def test_tool_reference_documents_every_public_tool_and_default_off_admin_flags() -> None:
    for name in (
        "bitwarden_status", "bitwarden_project_list", "bitwarden_project_get", "bitwarden_secret_list",
        "bitwarden_secret_get", "bitwarden_secret_write_file", "bitwarden_secret_write_env_file",
        "bitwarden_secret_create_from_file", "bitwarden_secret_update_from_file", "bitwarden_secret_delete",
        "bitwarden_project_create", "bitwarden_project_update", "bitwarden_project_delete",
    ):
        assert f"`{name}`" in TOOLS
    for flag in (
        "allow_secret_create", "allow_secret_update", "allow_secret_delete",
        "allow_project_create", "allow_project_update", "allow_project_delete",
    ):
        assert f"`{flag}`" in TOOLS
    assert "default" in TOOLS.lower() and "disabled" in TOOLS.lower()


def test_security_policy_states_value_boundaries_and_no_command_execution() -> None:
    text = SECURITY.lower()
    assert "secret values" in text
    assert "mcp responses" in text
    assert "logs" in text
    assert "command execution" in text
