from __future__ import annotations

import re
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class ProfileInput(StrictModel):
    profile: str | None = Field(default=None, min_length=1, max_length=128)


class ProjectGetInput(ProfileInput):
    project_id: UUID


class SecretListInput(ProfileInput):
    project_id: UUID | None = None
    query: str | None = Field(default=None, min_length=1, max_length=256)


class SecretGetInput(ProfileInput):
    identifier: str = Field(min_length=1, max_length=512)
    project_id: UUID | None = None


class SecretWriteFileInput(SecretGetInput):
    target_path: str = Field(min_length=1, max_length=4096)


class SecretWriteEnvFileInput(ProfileInput):
    target_path: str = Field(min_length=1, max_length=4096)
    secrets: dict[str, str] = Field(min_length=1, max_length=128)
    project_id: UUID | None = None

    @field_validator("secrets")
    @classmethod
    def validate_mapping(cls, value: dict[str, str]) -> dict[str, str]:
        for key, identifier in value.items():
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) is None:
                raise ValueError(f"Invalid environment variable name: {key}")
            if not isinstance(identifier, str) or not identifier.strip() or len(identifier) > 512:
                raise ValueError(f"Secret identifier for {key} must be a non-empty string up to 512 characters")
        return value


class SecretGenerateInput(ProfileInput):
    project_id: UUID
    key: str = Field(min_length=1, max_length=256)
    length: int = Field(default=32, ge=5, le=128)
    uppercase: bool = True
    lowercase: bool = True
    digits: bool = True
    special: bool = True
    min_digits: int = Field(default=1, ge=0, le=128)
    min_special: int = Field(default=1, ge=0, le=128)
    avoid_ambiguous: bool = True

    @model_validator(mode="after")
    def validate_policy(self) -> "SecretGenerateInput":
        if not any((self.uppercase, self.lowercase, self.digits, self.special)):
            raise ValueError("At least one character class must be enabled")
        if self.min_digits and not self.digits:
            raise ValueError("min_digits requires digits to be enabled")
        if self.min_special and not self.special:
            raise ValueError("min_special requires special characters to be enabled")
        if self.min_digits + self.min_special > self.length:
            raise ValueError("Minimum character counts exceed password length")
        return self


class SecretCreateFromFileInput(ProfileInput):
    project_id: UUID
    key: str = Field(min_length=1, max_length=256)
    source_path: str = Field(min_length=1, max_length=4096)


class SecretUpdateFromFileInput(ProfileInput):
    project_id: UUID
    identifier: str = Field(min_length=1, max_length=512)
    source_path: str = Field(min_length=1, max_length=4096)


class SecretDeleteInput(ProfileInput):
    project_id: UUID
    identifier: str = Field(min_length=1, max_length=512)
    expected_key: str = Field(min_length=1, max_length=256)
    confirm: Literal[True]


class ProjectCreateInput(ProfileInput):
    name: str = Field(min_length=1, max_length=256)


class ProjectUpdateInput(ProfileInput):
    project_id: UUID
    name: str = Field(min_length=1, max_length=256)


class ProjectDeleteInput(ProfileInput):
    project_id: UUID
    expected_name: str = Field(min_length=1, max_length=256)
    confirm: Literal[True]
