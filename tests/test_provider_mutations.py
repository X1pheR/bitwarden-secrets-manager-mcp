from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

from bitwarden_secrets_manager_mcp.config import ProfileSettings
from bitwarden_secrets_manager_mcp.provider import SdkProvider

ORG = UUID("77dda5e6-1775-4d24-9f28-b4790145d99b")
PROJECT = UUID("914c6a08-47fd-4da1-9f79-b4a10151c2a3")
SECRET = UUID("11111111-1111-4111-8111-111111111111")
NOW = datetime(2026, 8, 15, tzinfo=timezone.utc)


def response(data=None, success=True): return SimpleNamespace(success=success, data=data)
def project(name="Runtime"): return SimpleNamespace(id=PROJECT, name=name, organization_id=ORG, creation_date=NOW, revision_date=NOW)
def secret(value="old", note="private-note"): return SimpleNamespace(id=SECRET, key="TOKEN", value=value, note=note, organization_id=ORG, project_id=PROJECT, creation_date=NOW, revision_date=NOW)


class Projects:
    def __init__(self): self.calls=[]
    def list(self, organization_id): return response(SimpleNamespace(data=[project()]))
    def create(self, organization_id, name): self.calls.append(("create", organization_id, name)); return response(project(name))
    def update(self, organization_id, project_id, name): self.calls.append(("update", organization_id, project_id, name)); return response(project(name))
    def delete(self, ids): self.calls.append(("delete", ids)); return response(success=True)


class Secrets:
    def __init__(self): self.calls=[]
    def list(self, organization_id): return response(SimpleNamespace(data=[SimpleNamespace(id=SECRET,key="TOKEN",organization_id=ORG,project_ids=[PROJECT])]))
    def get(self, secret_id): return response(secret())
    def create(self, organization_id, key, value, note, project_ids): self.calls.append(("create",organization_id,key,value,note,project_ids)); return response(secret(value, note or ""))
    def update(self, organization_id, secret_id, key, value, note, project_ids): self.calls.append(("update",organization_id,secret_id,key,value,note,project_ids)); return response(secret(value,note))
    def delete(self, ids): self.calls.append(("delete",ids)); return response(success=True)


class Client:
    def __init__(self): self.p=Projects(); self.s=Secrets()
    def projects(self): return self.p
    def secrets(self): return self.s


def make_profile(tmp_path: Path):
    token=tmp_path/"token"; token.write_text("x"); token.chmod(0o600)
    return ProfileSettings("test",token,ORG,"https://api.bitwarden.eu","https://identity.bitwarden.eu",("Runtime",),(),())


def test_secret_update_preserves_key_note_project_but_returns_no_value(tmp_path: Path) -> None:
    client=Client(); provider=SdkProvider(make_profile(tmp_path),client=client)
    result=provider.update_secret(str(PROJECT),str(SECRET),"new-secret")
    call=client.s.calls[-1]
    assert call[0] == "update"
    assert call[4] == "new-secret"
    assert call[5] == "private-note"
    assert call[6] == [PROJECT]
    assert "value" not in result and "note" not in result and "new-secret" not in repr(result)


def test_deletes_are_exact_single_resource_sdk_calls(tmp_path: Path) -> None:
    client=Client(); provider=SdkProvider(make_profile(tmp_path),client=client)
    provider.delete_secret(str(PROJECT),str(SECRET),expected_key="TOKEN")
    assert client.s.calls[-1] == ("delete", [str(SECRET)])
    provider.delete_project(str(PROJECT),expected_name="Runtime")
    assert client.p.calls[-1] == ("delete", [str(PROJECT)])


def test_project_crud_uses_typed_sdk_surface(tmp_path: Path) -> None:
    client=Client(); provider=SdkProvider(make_profile(tmp_path),client=client)
    assert provider.create_project("Temporary")["name"] == "Temporary"
    assert provider.update_project(str(PROJECT),"Renamed")["name"] == "Renamed"
