from __future__ import annotations

from datetime import datetime
from typing import Any, Callable, TypeVar
from uuid import UUID

from .config import ConfigurationError, ProfileSettings


class ProviderError(RuntimeError):
    """A deliberately redacted provider failure."""


T = TypeVar("T")


def _iso(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        text = value.isoformat()
        return text.replace("+00:00", "Z")
    return str(value)


def _project_metadata(project: Any) -> dict[str, Any]:
    return {
        "id": str(project.id),
        "name": str(project.name),
        "organizationId": str(project.organization_id),
        "creationDate": _iso(getattr(project, "creation_date", None)),
        "revisionDate": _iso(getattr(project, "revision_date", None)),
    }


def _secret_identifier_metadata(secret: Any) -> dict[str, Any]:
    return {
        "id": str(secret.id),
        "key": str(secret.key),
        "organizationId": str(secret.organization_id),
        "projectIds": [str(item) for item in getattr(secret, "project_ids", [])],
    }


def _secret_metadata(secret: Any) -> dict[str, Any]:
    project_id = getattr(secret, "project_id", None)
    return {
        "id": str(secret.id),
        "key": str(secret.key),
        "organizationId": str(secret.organization_id),
        "projectIds": [str(project_id)] if project_id is not None else [],
        "creationDate": _iso(getattr(secret, "creation_date", None)),
        "revisionDate": _iso(getattr(secret, "revision_date", None)),
    }


class SdkProvider:
    """Single provider path backed only by the official Bitwarden SDK."""

    def __init__(self, profile: ProfileSettings, *, client: Any | None = None) -> None:
        self.profile = profile
        self.client = client if client is not None else self._build_client()

    def _build_client(self) -> Any:
        try:
            from bitwarden_sdk import BitwardenClient, DeviceType, client_settings_from_dict

            client = BitwardenClient(
                client_settings_from_dict(
                    {
                        "apiUrl": self.profile.api_url,
                        "identityUrl": self.profile.identity_url,
                        "deviceType": DeviceType.SDK,
                        "userAgent": "Bitwarden Secrets Manager MCP/0.1.0",
                    }
                )
            )
            client.auth().login_access_token(self.profile.read_access_token())
            return client
        except ConfigurationError:
            raise
        except Exception as exc:
            raise ProviderError("Bitwarden SDK authentication failed") from exc

    def _call(self, label: str, operation: Callable[[], T]) -> T:
        try:
            return operation()
        except ProviderError:
            raise
        except Exception as exc:
            raise ProviderError(f"Bitwarden SDK {label} failed") from exc

    @staticmethod
    def _response_data(response: Any, label: str) -> Any:
        if getattr(response, "success", True) is False or not hasattr(response, "data"):
            raise ProviderError(f"Bitwarden SDK {label} failed")
        return response.data

    def list_projects(self) -> list[dict[str, Any]]:
        response = self._call("project list", lambda: self.client.projects().list(str(self.profile.organization_id)))
        data = self._response_data(response, "project list")
        return [_project_metadata(item) for item in data.data]

    def assert_expected_scope(self) -> list[dict[str, Any]]:
        projects = self.list_projects()
        observed = sorted(item["name"] for item in projects)
        expected = sorted(self.profile.expected_project_names)
        if observed != expected:
            raise ProviderError(f"Bitwarden project scope mismatch for profile {self.profile.name}")
        return projects

    def assert_project_id(self, project_id: str) -> dict[str, Any]:
        try:
            wanted = str(UUID(project_id))
        except ValueError as exc:
            raise ProviderError("Bitwarden project_id must be a UUID") from exc
        matches = [item for item in self.assert_expected_scope() if item["id"] == wanted]
        if len(matches) != 1:
            raise ProviderError(f"Bitwarden project is outside the exact scope for profile {self.profile.name}")
        return matches[0]

    def get_project(self, project_id: str) -> dict[str, Any]:
        self.assert_project_id(project_id)
        response = self._call("project get", lambda: self.client.projects().get(project_id))
        return _project_metadata(self._response_data(response, "project get"))

    def list_secret_identifiers(self, project_id: str | None = None) -> list[dict[str, Any]]:
        if project_id is not None:
            self.assert_project_id(project_id)
        else:
            self.assert_expected_scope()
        response = self._call("secret list", lambda: self.client.secrets().list(str(self.profile.organization_id)))
        data = self._response_data(response, "secret list")
        items = [_secret_identifier_metadata(item) for item in data.data]
        if project_id is not None:
            items = [item for item in items if project_id in item["projectIds"]]
        return items

    def resolve_secret(self, identifier: str, project_id: str | None = None) -> dict[str, Any]:
        items = self.list_secret_identifiers(project_id)
        try:
            normalized = str(UUID(identifier))
        except ValueError:
            normalized = None
        if normalized is not None:
            matches = [item for item in items if item["id"] == normalized]
        else:
            matches = [item for item in items if item["key"] == identifier]
        if not matches:
            raise ProviderError("Bitwarden secret was not found in the exact profile scope")
        if len(matches) != 1:
            raise ProviderError("Bitwarden secret identifier is ambiguous in the exact profile scope")
        return matches[0]

    def _get_secret_record(self, secret_id: str) -> Any:
        response = self._call("secret get", lambda: self.client.secrets().get(secret_id))
        return self._response_data(response, "secret get")

    def get_secret_metadata(self, identifier: str, project_id: str | None = None) -> dict[str, Any]:
        resolved = self.resolve_secret(identifier, project_id)
        return _secret_metadata(self._get_secret_record(resolved["id"]))

    def get_secret_value(self, identifier: str, project_id: str | None = None) -> str:
        resolved = self.resolve_secret(identifier, project_id)
        record = self._get_secret_record(resolved["id"])
        value = getattr(record, "value", None)
        if not isinstance(value, str):
            raise ProviderError("Bitwarden SDK secret get returned an invalid value")
        return value

    def create_secret(self, project_id: str, key: str, value: str) -> dict[str, Any]:
        self.assert_project_id(project_id)
        response = self._call(
            "secret create",
            lambda: self.client.secrets().create(self.profile.organization_id, key, value, None, [UUID(project_id)]),
        )
        return _secret_metadata(self._response_data(response, "secret create"))

    def update_secret(self, project_id: str, identifier: str, value: str) -> dict[str, Any]:
        self.assert_project_id(project_id)
        resolved = self.resolve_secret(identifier, project_id)
        existing = self._get_secret_record(resolved["id"])
        response = self._call(
            "secret update",
            lambda: self.client.secrets().update(
                str(self.profile.organization_id),
                resolved["id"],
                str(existing.key),
                value,
                getattr(existing, "note", None),
                [UUID(project_id)],
            ),
        )
        return _secret_metadata(self._response_data(response, "secret update"))

    def delete_secret(self, project_id: str, identifier: str, *, expected_key: str) -> dict[str, Any]:
        self.assert_project_id(project_id)
        resolved = self.resolve_secret(identifier, project_id)
        if resolved["key"] != expected_key:
            raise ProviderError("Bitwarden secret expected_key does not match the resolved secret")
        response = self._call("secret delete", lambda: self.client.secrets().delete([resolved["id"]]))
        if getattr(response, "success", False) is not True:
            raise ProviderError("Bitwarden SDK secret delete failed")
        return resolved

    def create_project(self, name: str) -> dict[str, Any]:
        self.assert_expected_scope()
        response = self._call("project create", lambda: self.client.projects().create(str(self.profile.organization_id), name))
        return _project_metadata(self._response_data(response, "project create"))

    def update_project(self, project_id: str, name: str) -> dict[str, Any]:
        self.assert_project_id(project_id)
        response = self._call(
            "project update",
            lambda: self.client.projects().update(str(self.profile.organization_id), project_id, name),
        )
        return _project_metadata(self._response_data(response, "project update"))

    def delete_project(self, project_id: str, *, expected_name: str) -> dict[str, Any]:
        project = self.assert_project_id(project_id)
        if project["name"] != expected_name:
            raise ProviderError("Bitwarden project expected_name does not match the resolved project")
        response = self._call("project delete", lambda: self.client.projects().delete([project_id]))
        if getattr(response, "success", False) is not True:
            raise ProviderError("Bitwarden SDK project delete failed")
        return project
