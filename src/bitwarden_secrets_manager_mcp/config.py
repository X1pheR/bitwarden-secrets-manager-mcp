from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from uuid import UUID


class ConfigurationError(ValueError):
    """Raised when server configuration fails closed."""


_CLOUD_ENDPOINTS = {
    "us": ("https://api.bitwarden.com", "https://identity.bitwarden.com"),
    "eu": ("https://api.bitwarden.eu", "https://identity.bitwarden.eu"),
}
_CAPABILITIES = {
    "secret_create": "allow_secret_create",
    "secret_update": "allow_secret_update",
    "secret_delete": "allow_secret_delete",
    "project_create": "allow_project_create",
    "project_update": "allow_project_update",
    "project_delete": "allow_project_delete",
}
_PROFILE_FIELDS = {
    "access_token_file",
    "organization_id",
    "environment",
    "api_url",
    "identity_url",
    "expected_project_names",
    "allowed_input_directories",
    "allowed_output_directories",
    *_CAPABILITIES.values(),
}


def _parse_mode(value: str | int) -> int:
    try:
        mode = int(value, 8) if isinstance(value, str) else int(value)
    except (TypeError, ValueError) as exc:
        raise ConfigurationError("BITWARDEN_SM_DEFAULT_FILE_MODE must be an octal mode such as 0600") from exc
    if mode < 0o600 or mode > 0o660 or mode & 0o007:
        raise ConfigurationError("Default file mode must be between 0600 and 0660 with no world permissions")
    if mode & 0o111:
        raise ConfigurationError("Default file mode must not contain executable bits")
    return mode


def _validate_url(value: str, label: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ConfigurationError(f"{label} must be an absolute http(s) URL")
    if parsed.query or parsed.fragment:
        raise ConfigurationError(f"{label} must not contain a query or fragment")
    return value.rstrip("/")


def _resolve_dirs(raw: Any, *, profile: str, label: str) -> tuple[Path, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list) or not all(isinstance(item, str) and item.strip() for item in raw):
        raise ConfigurationError(f"Profile {profile} {label} must be an array of absolute paths")
    resolved: list[Path] = []
    for item in raw:
        path = Path(item)
        if not path.is_absolute():
            raise ConfigurationError(f"Profile {profile} {label} must contain only absolute paths")
        resolved.append(path.resolve(strict=False))
    if len(set(resolved)) != len(resolved):
        raise ConfigurationError(f"Profile {profile} {label} contains duplicate paths")
    return tuple(resolved)


def _assert_private_regular_file(path: Path, *, label: str) -> os.stat_result:
    if not path.is_absolute():
        raise ConfigurationError(f"{label} must be an absolute path")
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise ConfigurationError(f"{label} does not exist") from exc
    if stat.S_ISLNK(info.st_mode):
        raise ConfigurationError(f"{label} must not be a symlink")
    if not stat.S_ISREG(info.st_mode):
        raise ConfigurationError(f"{label} must be a regular file")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise ConfigurationError(f"{label} must be private (0600 or stricter)")
    return info


@dataclass(frozen=True)
class ProfileSettings:
    name: str
    access_token_file: Path
    organization_id: UUID
    api_url: str
    identity_url: str
    expected_project_names: tuple[str, ...]
    allowed_input_directories: tuple[Path, ...]
    allowed_output_directories: tuple[Path, ...]
    file_mode: int = 0o600
    allow_secret_create: bool = False
    allow_secret_update: bool = False
    allow_secret_delete: bool = False
    allow_project_create: bool = False
    allow_project_update: bool = False
    allow_project_delete: bool = False

    @property
    def delivery_write_enabled(self) -> bool:
        return bool(self.allowed_output_directories)

    def read_access_token(self) -> str:
        label = f"Profile {self.name} access_token_file"
        _assert_private_regular_file(self.access_token_file, label=label)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(self.access_token_file, flags)
        except OSError as exc:
            raise ConfigurationError(f"{label} could not be opened safely") from exc
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise ConfigurationError(f"{label} must remain a regular file")
            if stat.S_IMODE(info.st_mode) & 0o077:
                raise ConfigurationError(f"{label} must remain private (0600 or stricter)")
            try:
                with os.fdopen(fd, "r", encoding="utf-8", closefd=False) as handle:
                    token = handle.read().strip()
            except UnicodeDecodeError as exc:
                raise ConfigurationError(f"{label} must contain UTF-8 text") from exc
        finally:
            os.close(fd)
        if not token:
            raise ConfigurationError(f"{label} is empty")
        return token


def _profile_from_mapping(name: str, raw: Any, *, default_file_mode: int) -> ProfileSettings:
    if not isinstance(raw, dict):
        raise ConfigurationError(f"Profile {name} must be a JSON object")
    unknown = sorted(set(raw) - _PROFILE_FIELDS)
    if unknown:
        raise ConfigurationError(f"Unknown profile fields for {name}: {', '.join(unknown)}")

    token_raw = raw.get("access_token_file")
    if not isinstance(token_raw, str) or not token_raw.strip():
        raise ConfigurationError(f"Profile {name} access_token_file is required")
    token_file = Path(token_raw)
    _assert_private_regular_file(token_file, label=f"Profile {name} access_token_file")

    try:
        organization_id = UUID(str(raw.get("organization_id", "")))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ConfigurationError(f"Profile {name} organization_id must be a UUID") from exc

    environment = raw.get("environment")
    if environment not in {"us", "eu", "custom"}:
        raise ConfigurationError(f"Profile {name} environment must be one of: us, eu, custom")
    api_raw = raw.get("api_url")
    identity_raw = raw.get("identity_url")
    if environment == "custom":
        if not isinstance(api_raw, str) or not isinstance(identity_raw, str):
            raise ConfigurationError(f"Profile {name} custom environment requires api_url and identity_url")
        api_url = _validate_url(api_raw, f"Profile {name} api_url")
        identity_url = _validate_url(identity_raw, f"Profile {name} identity_url")
    else:
        if api_raw is not None or identity_raw is not None:
            raise ConfigurationError(f"Profile {name} api_url and identity_url are only valid with environment custom")
        api_url, identity_url = _CLOUD_ENDPOINTS[environment]

    expected = raw.get("expected_project_names")
    if not isinstance(expected, list) or not expected or not all(isinstance(item, str) and item.strip() for item in expected):
        raise ConfigurationError(f"Profile {name} expected_project_names must be a non-empty array of names")
    expected_names = tuple(item.strip() for item in expected)
    if len(set(expected_names)) != len(expected_names):
        raise ConfigurationError(f"Profile {name} expected_project_names must be unique")

    capabilities: dict[str, bool] = {}
    for field in _CAPABILITIES.values():
        value = raw.get(field, False)
        if not isinstance(value, bool):
            raise ConfigurationError(f"Profile {name} {field} must be true or false")
        capabilities[field] = value

    return ProfileSettings(
        name=name,
        access_token_file=token_file,
        organization_id=organization_id,
        api_url=api_url,
        identity_url=identity_url,
        expected_project_names=expected_names,
        allowed_input_directories=_resolve_dirs(raw.get("allowed_input_directories", []), profile=name, label="allowed_input_directories"),
        allowed_output_directories=_resolve_dirs(raw.get("allowed_output_directories", []), profile=name, label="allowed_output_directories"),
        file_mode=default_file_mode,
        **capabilities,
    )


@dataclass(frozen=True)
class Settings:
    profiles: dict[str, ProfileSettings]

    @classmethod
    def from_file(cls, path: Path, *, default_file_mode: int = 0o600) -> "Settings":
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise ConfigurationError(f"Profiles file does not exist: {path}") from exc
        except json.JSONDecodeError as exc:
            raise ConfigurationError("Profiles file is not valid JSON") from exc
        if not isinstance(raw, dict) or set(raw) != {"profiles"} or not isinstance(raw.get("profiles"), dict):
            raise ConfigurationError("Profiles file must contain exactly one top-level profiles object")
        if not raw["profiles"]:
            raise ConfigurationError("Profiles file must configure at least one profile")
        profiles: dict[str, ProfileSettings] = {}
        for name, profile_raw in raw["profiles"].items():
            if not isinstance(name, str) or not name.strip():
                raise ConfigurationError("Profile names must be non-empty strings")
            profiles[name] = _profile_from_mapping(name, profile_raw, default_file_mode=default_file_mode)
        return cls(profiles=profiles)

    @classmethod
    def from_env(cls) -> "Settings":
        value = os.environ.get("BITWARDEN_SM_PROFILES_FILE", "").strip()
        if not value:
            raise ConfigurationError("BITWARDEN_SM_PROFILES_FILE is required")
        path = Path(value)
        if not path.is_absolute():
            raise ConfigurationError("BITWARDEN_SM_PROFILES_FILE must be an absolute path")
        mode = _parse_mode(os.environ.get("BITWARDEN_SM_DEFAULT_FILE_MODE", "0600"))
        return cls.from_file(path, default_file_mode=mode)

    def select_profiles(self, name: str | None) -> tuple[ProfileSettings, ...]:
        if name is None:
            return tuple(self.profiles[key] for key in sorted(self.profiles))
        try:
            return (self.profiles[name],)
        except KeyError as exc:
            raise ConfigurationError(f"Unknown Bitwarden Secrets Manager profile: {name}") from exc

    def select_single_profile(self, name: str | None, *, action: str) -> ProfileSettings:
        selected = self.select_profiles(name)
        if len(selected) != 1:
            raise ConfigurationError(f"profile is required for {action} when multiple profiles are configured")
        return selected[0]

    def select_mutation_profile(self, name: str | None, operation: str) -> ProfileSettings:
        try:
            capability = _CAPABILITIES[operation]
        except KeyError as exc:
            raise ConfigurationError(f"Unknown mutation operation: {operation}") from exc
        profile = self.select_single_profile(name, action=operation.replace("_", " "))
        if not getattr(profile, capability):
            raise ConfigurationError(f"{operation.replace('_', ' ')} is disabled for profile {profile.name}")
        return profile
