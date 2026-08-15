from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import pytest

from bitwarden_secrets_manager_mcp.config import ProfileSettings
from bitwarden_secrets_manager_mcp.provider import ProviderError, SdkProvider

ORG = UUID("77dda5e6-1775-4d24-9f28-b4790145d99b")
PROJECT = UUID("914c6a08-47fd-4da1-9f79-b4a10151c2a3")
SECRET = UUID("11111111-1111-4111-8111-111111111111")
NOW = datetime(2026, 8, 15, tzinfo=timezone.utc)


def profile(tmp_path: Path) -> ProfileSettings:
    token = tmp_path / "token"
    token.write_text("machine-token", encoding="utf-8")
    token.chmod(0o600)
    return ProfileSettings(
        name="test",
        access_token_file=token,
        organization_id=ORG,
        api_url="https://api.bitwarden.eu",
        identity_url="https://identity.bitwarden.eu",
        expected_project_names=("Runtime",),
        allowed_input_directories=(),
        allowed_output_directories=(),
        file_mode=0o600,
    )


def response(data):
    return SimpleNamespace(success=True, data=data)


def project_obj(name: str = "Runtime"):
    return SimpleNamespace(id=PROJECT, name=name, organization_id=ORG, creation_date=NOW, revision_date=NOW)


def secret_obj(value: str = "TOP-SECRET", note: str = "also-sensitive"):
    return SimpleNamespace(
        id=SECRET,
        key="SERVICE_TOKEN",
        value=value,
        note=note,
        organization_id=ORG,
        project_id=PROJECT,
        creation_date=NOW,
        revision_date=NOW,
    )


class FakeProjects:
    def __init__(self, names=("Runtime",)):
        self.names = names

    def list(self, organization_id):
        assert organization_id == str(ORG)
        return response(SimpleNamespace(data=[project_obj(name) for name in self.names]))

    def get(self, project_id):
        assert str(project_id) == str(PROJECT)
        return response(project_obj())


class FakeSecrets:
    def list(self, organization_id):
        assert organization_id == str(ORG)
        identifier = SimpleNamespace(id=SECRET, key="SERVICE_TOKEN", organization_id=ORG, project_ids=[PROJECT])
        return response(SimpleNamespace(data=[identifier]))

    def get(self, secret_id):
        assert str(secret_id) == str(SECRET)
        return response(secret_obj())


class FakeClient:
    def __init__(self, projects=None, secrets=None):
        self._projects = projects or FakeProjects()
        self._secrets = secrets or FakeSecrets()

    def projects(self):
        return self._projects

    def secrets(self):
        return self._secrets


def test_project_and_secret_metadata_never_include_secret_value_or_note(tmp_path: Path) -> None:
    provider = SdkProvider(profile(tmp_path), client=FakeClient())
    assert provider.list_projects()[0]["name"] == "Runtime"
    metadata = provider.get_secret_metadata(str(SECRET))
    assert metadata["key"] == "SERVICE_TOKEN"
    assert "value" not in metadata
    assert "note" not in metadata
    assert "TOP-SECRET" not in repr(metadata)
    assert "also-sensitive" not in repr(metadata)


def test_expected_project_scope_is_exact_and_fails_closed(tmp_path: Path) -> None:
    provider = SdkProvider(profile(tmp_path), client=FakeClient(projects=FakeProjects(("Runtime", "Unexpected"))))
    with pytest.raises(ProviderError, match="project scope mismatch"):
        provider.assert_expected_scope()


def test_provider_errors_do_not_echo_sdk_exception_text(tmp_path: Path) -> None:
    class ExplodingProjects(FakeProjects):
        def list(self, organization_id):
            raise RuntimeError("TOP-SECRET leaked by upstream")

    provider = SdkProvider(profile(tmp_path), client=FakeClient(projects=ExplodingProjects()))
    with pytest.raises(ProviderError) as exc:
        provider.list_projects()
    assert "TOP-SECRET" not in str(exc.value)


def test_secret_resolution_by_key_is_exact_and_project_scoped(tmp_path: Path) -> None:
    provider = SdkProvider(profile(tmp_path), client=FakeClient())
    resolved = provider.resolve_secret("SERVICE_TOKEN", str(PROJECT))
    assert resolved["id"] == str(SECRET)
    assert "value" not in resolved


def test_secret_discovery_excludes_unassigned_or_unexpected_project_links(tmp_path: Path) -> None:
    expected = SimpleNamespace(id=SECRET, key="EXPECTED", organization_id=ORG, project_ids=[PROJECT])
    unassigned = SimpleNamespace(id=UUID("22222222-2222-4222-8222-222222222222"), key="UNASSIGNED", organization_id=ORG, project_ids=[])
    unexpected = SimpleNamespace(id=UUID("33333333-3333-4333-8333-333333333333"), key="UNEXPECTED", organization_id=ORG, project_ids=[UUID("44444444-4444-4444-8444-444444444444")])

    class ScopedSecrets(FakeSecrets):
        def list(self, organization_id):
            return response(SimpleNamespace(data=[expected, unassigned, unexpected]))

    provider = SdkProvider(profile(tmp_path), client=FakeClient(secrets=ScopedSecrets()))
    items = provider.list_secret_identifiers()
    assert [item["key"] for item in items] == ["EXPECTED"]
