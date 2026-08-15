from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from .config import ProfileSettings, Settings
from .delivery import atomic_write, env_payload
from .provider import SdkProvider
from .sources import read_secret_source


ProviderFactory = Callable[[ProfileSettings], SdkProvider]


def _tag_profile(metadata: dict[str, Any], profile: ProfileSettings) -> dict[str, Any]:
    return {**metadata, "profile": profile.name}


class BitwardenSecretsManagerService:
    def __init__(self, settings: Settings, *, provider_factory: ProviderFactory | None = None) -> None:
        self.settings = settings
        self.provider_factory = provider_factory or (lambda profile: SdkProvider(profile))

    def _provider(self, profile: ProfileSettings) -> SdkProvider:
        return self.provider_factory(profile)

    def status(self, profile_name: str | None = None) -> dict[str, Any]:
        statuses: list[dict[str, Any]] = []
        for profile in self.settings.select_profiles(profile_name):
            projects = self._provider(profile).assert_expected_scope()
            statuses.append(
                {
                    "profile": profile.name,
                    "ready": True,
                    "apiUrl": profile.api_url,
                    "identityUrl": profile.identity_url,
                    "organizationId": str(profile.organization_id),
                    "expectedProjectNames": list(profile.expected_project_names),
                    "projectCount": len(projects),
                    "allowedInputDirectories": [str(path) for path in profile.allowed_input_directories],
                    "allowedOutputDirectories": [str(path) for path in profile.allowed_output_directories],
                    "deliveryWriteEnabled": profile.delivery_write_enabled,
                    "capabilities": {
                        "secretCreate": profile.allow_secret_create,
                        "secretUpdate": profile.allow_secret_update,
                        "secretDelete": profile.allow_secret_delete,
                        "projectCreate": profile.allow_project_create,
                        "projectUpdate": profile.allow_project_update,
                        "projectDelete": profile.allow_project_delete,
                    },
                }
            )
        return {"ready": True, "provider": "bitwarden-sdk", "profiles": statuses}

    def project_list(self, profile_name: str | None = None) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for profile in self.settings.select_profiles(profile_name):
            projects = self._provider(profile).assert_expected_scope()
            result.extend(_tag_profile(item, profile) for item in projects)
        return result

    def project_get(self, profile_name: str | None, project_id: str) -> dict[str, Any]:
        profile = self.settings.select_single_profile(profile_name, action="project get")
        return _tag_profile(self._provider(profile).get_project(project_id), profile)

    def secret_list(
        self,
        profile_name: str | None = None,
        project_id: str | None = None,
        query: str | None = None,
    ) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        needle = query.casefold() if query else None
        for profile in self.settings.select_profiles(profile_name):
            items = self._provider(profile).list_secret_identifiers(project_id)
            for item in items:
                if needle is not None and needle not in item["key"].casefold():
                    continue
                result.append(_tag_profile(item, profile))
        return result

    def secret_get(self, profile_name: str | None, identifier: str, project_id: str | None = None) -> dict[str, Any]:
        profile = self.settings.select_single_profile(profile_name, action="secret get")
        return _tag_profile(self._provider(profile).get_secret_metadata(identifier, project_id), profile)

    def secret_write_file(
        self,
        profile_name: str | None,
        identifier: str,
        target_path: str,
        project_id: str | None = None,
    ) -> dict[str, Any]:
        profile = self.settings.select_single_profile(profile_name, action="secret file delivery")
        if not profile.delivery_write_enabled:
            raise ValueError(f"Secret file delivery is disabled for profile {profile.name}")
        provider = self._provider(profile)
        metadata = provider.get_secret_metadata(identifier, project_id)
        value = provider.get_secret_value(identifier, project_id)
        try:
            target = atomic_write(profile, target_path, value.encode("utf-8"))
        finally:
            value = ""
        return {"written": True, "targetPath": str(target), "secret": metadata, "profile": profile.name}

    def secret_write_env_file(
        self,
        profile_name: str | None,
        target_path: str,
        secrets: Mapping[str, str],
        project_id: str | None = None,
    ) -> dict[str, Any]:
        profile = self.settings.select_single_profile(profile_name, action="env file delivery")
        if not profile.delivery_write_enabled:
            raise ValueError(f"Secret env file delivery is disabled for profile {profile.name}")
        provider = self._provider(profile)
        values: dict[str, str] = {}
        try:
            for env_key, identifier in secrets.items():
                values[env_key] = provider.get_secret_value(identifier, project_id)
            target = atomic_write(profile, target_path, env_payload(values))
        finally:
            values.clear()
        return {
            "written": True,
            "targetPath": str(target),
            "profile": profile.name,
            "keys": sorted(secrets),
            "secretCount": len(secrets),
        }

    def secret_create_from_file(self, profile_name: str | None, project_id: str, key: str, source_path: str) -> dict[str, Any]:
        profile = self.settings.select_mutation_profile(profile_name, "secret_create")
        value = read_secret_source(profile, source_path)
        try:
            metadata = self._provider(profile).create_secret(project_id, key, value)
        finally:
            value = ""
        return {"created": True, "secret": metadata, "profile": profile.name}

    def secret_update_from_file(self, profile_name: str | None, project_id: str, identifier: str, source_path: str) -> dict[str, Any]:
        profile = self.settings.select_mutation_profile(profile_name, "secret_update")
        value = read_secret_source(profile, source_path)
        try:
            metadata = self._provider(profile).update_secret(project_id, identifier, value)
        finally:
            value = ""
        return {"updated": True, "secret": metadata, "profile": profile.name}

    def secret_delete(self, profile_name: str | None, project_id: str, identifier: str, *, expected_key: str) -> dict[str, Any]:
        profile = self.settings.select_mutation_profile(profile_name, "secret_delete")
        metadata = self._provider(profile).delete_secret(project_id, identifier, expected_key=expected_key)
        return {"deleted": True, "secret": metadata, "profile": profile.name}

    def project_create(self, profile_name: str | None, name: str) -> dict[str, Any]:
        profile = self.settings.select_mutation_profile(profile_name, "project_create")
        metadata = self._provider(profile).create_project(name)
        return {"created": True, "project": metadata, "profile": profile.name}

    def project_update(self, profile_name: str | None, project_id: str, name: str) -> dict[str, Any]:
        profile = self.settings.select_mutation_profile(profile_name, "project_update")
        metadata = self._provider(profile).update_project(project_id, name)
        return {"updated": True, "project": metadata, "profile": profile.name}

    def project_delete(self, profile_name: str | None, project_id: str, *, expected_name: str) -> dict[str, Any]:
        profile = self.settings.select_mutation_profile(profile_name, "project_delete")
        metadata = self._provider(profile).delete_project(project_id, expected_name=expected_name)
        return {"deleted": True, "project": metadata, "profile": profile.name}
