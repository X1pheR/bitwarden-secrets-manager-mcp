from __future__ import annotations

import json
from pathlib import Path

import pytest

from bitwarden_secrets_manager_mcp.config import ConfigurationError, Settings

ORG = "77dda5e6-1775-4d24-9f28-b4790145d99b"


def _private(path: Path, value: str = "machine-token") -> None:
    path.write_text(value, encoding="utf-8")
    path.chmod(0o600)


def _profiles(tmp_path: Path, profile: dict) -> Path:
    path = tmp_path / "profiles.json"
    path.write_text(json.dumps({"profiles": {"test": profile}}), encoding="utf-8")
    return path


def _base(tmp_path: Path) -> dict:
    token = tmp_path / "token"
    _private(token)
    incoming = tmp_path / "incoming"
    outgoing = tmp_path / "outgoing"
    incoming.mkdir()
    outgoing.mkdir()
    return {
        "access_token_file": str(token),
        "organization_id": ORG,
        "environment": "eu",
        "expected_project_names": ["Runtime"],
        "allowed_input_directories": [str(incoming)],
        "allowed_output_directories": [str(outgoing)],
    }


def test_profile_defaults_all_administrative_capabilities_off(tmp_path: Path) -> None:
    profile = _base(tmp_path)
    settings = Settings.from_file(_profiles(tmp_path, profile))
    selected = settings.profiles["test"]
    assert selected.api_url == "https://api.bitwarden.eu"
    assert selected.identity_url == "https://identity.bitwarden.eu"
    assert selected.allow_secret_create is False
    assert selected.allow_secret_update is False
    assert selected.allow_secret_delete is False
    assert selected.allow_project_create is False
    assert selected.allow_project_update is False
    assert selected.allow_project_delete is False


def test_custom_environment_requires_explicit_api_and_identity_urls(tmp_path: Path) -> None:
    profile = _base(tmp_path)
    profile["environment"] = "custom"
    with pytest.raises(ConfigurationError, match="api_url.*identity_url"):
        Settings.from_file(_profiles(tmp_path, profile))
    profile["api_url"] = "https://api.example.test"
    profile["identity_url"] = "https://identity.example.test"
    selected = Settings.from_file(_profiles(tmp_path, profile)).profiles["test"]
    assert selected.api_url == "https://api.example.test"
    assert selected.identity_url == "https://identity.example.test"


def test_cloud_environment_rejects_custom_url_overrides(tmp_path: Path) -> None:
    profile = _base(tmp_path)
    profile["api_url"] = "https://wrong.example.test"
    with pytest.raises(ConfigurationError, match="only valid.*custom"):
        Settings.from_file(_profiles(tmp_path, profile))


def test_profile_rejects_unknown_fields_and_legacy_server_url(tmp_path: Path) -> None:
    profile = _base(tmp_path)
    profile["server_url"] = "https://vault.bitwarden.eu"
    with pytest.raises(ConfigurationError, match="Unknown profile fields"):
        Settings.from_file(_profiles(tmp_path, profile))


def test_access_token_file_must_be_private_regular_non_symlink(tmp_path: Path) -> None:
    profile = _base(tmp_path)
    token = Path(profile["access_token_file"])
    token.chmod(0o644)
    with pytest.raises(ConfigurationError, match="private"):
        Settings.from_file(_profiles(tmp_path, profile))
    token.chmod(0o600)
    link = tmp_path / "token-link"
    link.symlink_to(token)
    profile["access_token_file"] = str(link)
    with pytest.raises(ConfigurationError, match="symlink"):
        Settings.from_file(_profiles(tmp_path, profile))


def test_mutation_selection_requires_explicit_profile_capability(tmp_path: Path) -> None:
    profile = _base(tmp_path)
    settings = Settings.from_file(_profiles(tmp_path, profile))
    with pytest.raises(ConfigurationError, match="project create.*disabled"):
        settings.select_mutation_profile("test", "project_create")
    profile["allow_project_create"] = True
    settings = Settings.from_file(_profiles(tmp_path, profile))
    assert settings.select_mutation_profile("test", "project_create").name == "test"


def test_settings_from_env_requires_profiles_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("BITWARDEN_SM_PROFILES_FILE", raising=False)
    with pytest.raises(ConfigurationError, match="BITWARDEN_SM_PROFILES_FILE"):
        Settings.from_env()


def test_default_file_mode_rejects_executable_bits(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    profile = _base(tmp_path)
    path = _profiles(tmp_path, profile)
    monkeypatch.setenv("BITWARDEN_SM_PROFILES_FILE", str(path))
    monkeypatch.setenv("BITWARDEN_SM_DEFAULT_FILE_MODE", "0650")
    with pytest.raises(ConfigurationError, match="executable"):
        Settings.from_env()
