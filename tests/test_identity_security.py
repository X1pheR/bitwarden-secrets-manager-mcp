from pathlib import Path
import tomllib

ROOT = Path(__file__).parents[1]


def test_distribution_and_entrypoint_use_only_new_identity() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert project["name"] == "bitwarden-secrets-manager-mcp"
    assert project["scripts"] == {"bitwarden-secrets-manager-mcp": "bitwarden_secrets_manager_mcp:main"}


def test_source_has_no_subprocess_or_legacy_provider_surface() -> None:
    source = "\n".join(path.read_text(encoding="utf-8") for path in (ROOT / "src").rglob("*.py"))
    for forbidden in ("subprocess", "BWS_BIN", "bws-secrets-mcp", "bws_secrets_mcp", "bws-secrets"):
        assert forbidden not in source
