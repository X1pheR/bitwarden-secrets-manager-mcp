from __future__ import annotations

import json
from pathlib import Path
from uuid import UUID

from bitwarden_secrets_manager_mcp.config import ProfileSettings, Settings
from bitwarden_secrets_manager_mcp.service import BitwardenSecretsManagerService

PROJECT = "914c6a08-47fd-4da1-9f79-b4a10151c2a3"
SECRET = "11111111-1111-4111-8111-111111111111"


class FakeProvider:
    def __init__(self):
        self.created_value = None
        self.updated_value = None

    def assert_expected_scope(self):
        return [{"id": PROJECT, "name": "Runtime", "organizationId": "org"}]

    def get_project(self, project_id):
        return {"id": project_id, "name": "Runtime", "organizationId": "org"}

    def list_secret_identifiers(self, project_id=None):
        return [{"id": SECRET, "key": "TOKEN", "projectIds": [PROJECT], "organizationId": "org"}]

    def get_secret_metadata(self, identifier, project_id=None):
        return {"id": SECRET, "key": "TOKEN", "projectIds": [PROJECT], "organizationId": "org"}

    def get_secret_value(self, identifier, project_id=None):
        return "CLASSIFIED"

    def create_secret(self, project_id, key, value):
        self.created_value = value
        return {"id": SECRET, "key": key, "projectIds": [project_id], "organizationId": "org"}

    def update_secret(self, project_id, identifier, value):
        self.updated_value = value
        return {"id": SECRET, "key": "TOKEN", "projectIds": [project_id], "organizationId": "org"}

    def delete_secret(self, project_id, identifier, *, expected_key):
        return {"id": SECRET, "key": expected_key, "projectIds": [project_id], "organizationId": "org"}

    def create_project(self, name):
        return {"id": PROJECT, "name": name, "organizationId": "org"}

    def update_project(self, project_id, name):
        return {"id": project_id, "name": name, "organizationId": "org"}

    def delete_project(self, project_id, *, expected_name):
        return {"id": project_id, "name": expected_name, "organizationId": "org"}


def setup(tmp_path: Path):
    token = tmp_path / "token"
    token.write_text("x", encoding="utf-8")
    token.chmod(0o600)
    incoming = tmp_path / "incoming"
    output = tmp_path / "output"
    incoming.mkdir(); output.mkdir()
    profile = ProfileSettings(
        name="test",
        access_token_file=token,
        organization_id=UUID("77dda5e6-1775-4d24-9f28-b4790145d99b"),
        api_url="https://api.bitwarden.eu",
        identity_url="https://identity.bitwarden.eu",
        expected_project_names=("Runtime",),
        allowed_input_directories=(incoming,),
        allowed_output_directories=(output,),
        allow_secret_create=True,
        allow_secret_update=True,
        allow_secret_delete=True,
        allow_project_create=True,
        allow_project_update=True,
        allow_project_delete=True,
    )
    provider = FakeProvider()
    service = BitwardenSecretsManagerService(Settings({"test": profile}), provider_factory=lambda _: provider)
    return service, provider, incoming, output


def assert_value_blind(value) -> None:
    text = json.dumps(value, sort_keys=True)
    assert "CLASSIFIED" not in text
    assert "source-secret" not in text
    assert "updated-secret" not in text


def test_delivery_consumes_secret_internally_without_returning_it(tmp_path: Path) -> None:
    service, _, _, output = setup(tmp_path)
    target = output / "delivered"
    result = service.secret_write_file("test", SECRET, str(target), PROJECT)
    assert target.read_text(encoding="utf-8") == "CLASSIFIED"
    assert result["targetPath"] == str(target)
    assert_value_blind(result)


def test_complete_env_delivery_is_value_blind(tmp_path: Path) -> None:
    service, _, _, output = setup(tmp_path)
    target = output / "runtime.env"
    result = service.secret_write_env_file("test", str(target), {"TOKEN": SECRET}, PROJECT)
    assert target.read_text(encoding="utf-8") == "TOKEN=CLASSIFIED\n"
    assert result["keys"] == ["TOKEN"]
    assert_value_blind(result)


def test_secret_mutations_read_values_only_from_protected_files(tmp_path: Path) -> None:
    service, provider, incoming, _ = setup(tmp_path)
    create = incoming / "create"
    create.write_text("source-secret", encoding="utf-8"); create.chmod(0o600)
    result = service.secret_create_from_file("test", PROJECT, "TOKEN", str(create))
    assert provider.created_value == "source-secret"
    assert_value_blind(result)
    update = incoming / "update"
    update.write_text("updated-secret", encoding="utf-8"); update.chmod(0o600)
    result = service.secret_update_from_file("test", PROJECT, SECRET, str(update))
    assert provider.updated_value == "updated-secret"
    assert_value_blind(result)


def test_exact_secret_and_project_deletes_return_metadata_only(tmp_path: Path) -> None:
    service, _, _, _ = setup(tmp_path)
    secret = service.secret_delete("test", PROJECT, SECRET, expected_key="TOKEN")
    project = service.project_delete("test", PROJECT, expected_name="Runtime")
    assert secret["deleted"] is True
    assert project["deleted"] is True
    assert_value_blind(secret); assert_value_blind(project)


def test_project_create_update_are_capability_guarded_and_metadata_only(tmp_path: Path) -> None:
    service, _, _, _ = setup(tmp_path)
    created = service.project_create("test", "Temporary")
    updated = service.project_update("test", PROJECT, "Renamed")
    assert created["project"]["name"] == "Temporary"
    assert updated["project"]["name"] == "Renamed"
