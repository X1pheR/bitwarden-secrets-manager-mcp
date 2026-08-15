from __future__ import annotations

import asyncio
import json
from collections.abc import Sequence
from typing import Any, TypeVar

import mcp.types as types
from mcp.server import Server
from pydantic import BaseModel, ValidationError

from .config import ConfigurationError, Settings
from .delivery import DeliveryError
from .models import (
    ProfileInput,
    ProjectCreateInput,
    ProjectDeleteInput,
    ProjectGetInput,
    ProjectUpdateInput,
    SecretCreateFromFileInput,
    SecretDeleteInput,
    SecretGetInput,
    SecretListInput,
    SecretUpdateFromFileInput,
    SecretWriteEnvFileInput,
    SecretWriteFileInput,
)
from .provider import ProviderError
from .service import BitwardenSecretsManagerService
from .sources import SourceError


mcp = Server("bitwarden-secrets-manager", version="0.1.0")
_settings: Settings | None = None
ModelT = TypeVar("ModelT", bound=BaseModel)


def configure(settings: Settings) -> None:
    global _settings
    _settings = settings


def _service() -> BitwardenSecretsManagerService:
    return BitwardenSecretsManagerService(_settings or Settings.from_env())


def _annotations(*, read_only: bool, destructive: bool = False, idempotent: bool | None = None) -> types.ToolAnnotations:
    return types.ToolAnnotations(
        readOnlyHint=read_only,
        destructiveHint=destructive,
        idempotentHint=idempotent,
        openWorldHint=True,
    )


def _tool(
    name: str,
    description: str,
    model: type[BaseModel],
    *,
    read_only: bool,
    destructive: bool = False,
    idempotent: bool | None = None,
) -> types.Tool:
    return types.Tool(
        name=name,
        description=description,
        inputSchema=model.model_json_schema(),
        annotations=_annotations(read_only=read_only, destructive=destructive, idempotent=idempotent),
    )


@mcp.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        _tool(
            "bitwarden_status",
            "Check configured Bitwarden Secrets Manager profiles, exact project scope, endpoints, and enabled capabilities. Secret values are never returned.",
            ProfileInput,
            read_only=True,
            idempotent=True,
        ),
        _tool(
            "bitwarden_project_list",
            "List project metadata within each profile's exact configured Bitwarden Secrets Manager scope.",
            ProfileInput,
            read_only=True,
            idempotent=True,
        ),
        _tool(
            "bitwarden_project_get",
            "Get one project's metadata after verifying it belongs to the profile's exact configured scope.",
            ProjectGetInput,
            read_only=True,
            idempotent=True,
        ),
        _tool(
            "bitwarden_secret_list",
            "List secret identifiers and project metadata without secret values or notes.",
            SecretListInput,
            read_only=True,
            idempotent=True,
        ),
        _tool(
            "bitwarden_secret_get",
            "Get one secret's metadata. The secret value and note are never returned through MCP.",
            SecretGetInput,
            read_only=True,
            idempotent=True,
        ),
        _tool(
            "bitwarden_secret_write_file",
            "Resolve one secret internally and atomically write only its value to an approved server-side file. The value is never returned.",
            SecretWriteFileInput,
            read_only=False,
            idempotent=True,
        ),
        _tool(
            "bitwarden_secret_write_env_file",
            "Resolve selected secrets internally and atomically replace one complete approved raw KEY=value env file. Values are never returned.",
            SecretWriteEnvFileInput,
            read_only=False,
            idempotent=True,
        ),
        _tool(
            "bitwarden_secret_create_from_file",
            "Create exactly one secret from a protected approved server-side source file. The profile capability is disabled by default and the value never passes through MCP arguments or responses.",
            SecretCreateFromFileInput,
            read_only=False,
        ),
        _tool(
            "bitwarden_secret_update_from_file",
            "Update exactly one secret from a protected approved server-side source file while preserving its key, note, and project. The profile capability is disabled by default.",
            SecretUpdateFromFileInput,
            read_only=False,
        ),
        _tool(
            "bitwarden_secret_delete",
            "Delete exactly one scoped secret after matching expected_key and explicit confirm=true. The profile capability is disabled by default.",
            SecretDeleteInput,
            read_only=False,
            destructive=True,
        ),
        _tool(
            "bitwarden_project_create",
            "Create one Bitwarden Secrets Manager project after exact pre-operation scope verification. The profile capability is disabled by default.",
            ProjectCreateInput,
            read_only=False,
        ),
        _tool(
            "bitwarden_project_update",
            "Rename one project that is already inside the profile's exact scope. The profile capability is disabled by default.",
            ProjectUpdateInput,
            read_only=False,
        ),
        _tool(
            "bitwarden_project_delete",
            "Delete exactly one scoped project after matching expected_name and explicit confirm=true. The profile capability is disabled by default.",
            ProjectDeleteInput,
            read_only=False,
            destructive=True,
        ),
    ]


def _validate(model: type[ModelT], arguments: Any) -> ModelT:
    try:
        return model.model_validate(arguments or {})
    except ValidationError as exc:
        raise ValueError("Invalid tool arguments") from exc


def _json_result(value: Any) -> Sequence[types.TextContent]:
    return [types.TextContent(type="text", text=json.dumps(value, sort_keys=True, separators=(",", ":"), default=str))]


@mcp.call_tool()
async def call_tool(name: str, arguments: Any) -> Sequence[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    known_tools = {tool.name for tool in await list_tools()}
    if name not in known_tools:
        raise ValueError(f"Unknown tool: {name}")
    service = _service()
    try:
        if name == "bitwarden_status":
            args = _validate(ProfileInput, arguments)
            result = service.status(args.profile)
        elif name == "bitwarden_project_list":
            args = _validate(ProfileInput, arguments)
            result = service.project_list(args.profile)
        elif name == "bitwarden_project_get":
            args = _validate(ProjectGetInput, arguments)
            result = service.project_get(args.profile, str(args.project_id))
        elif name == "bitwarden_secret_list":
            args = _validate(SecretListInput, arguments)
            result = service.secret_list(args.profile, str(args.project_id) if args.project_id else None, args.query)
        elif name == "bitwarden_secret_get":
            args = _validate(SecretGetInput, arguments)
            result = service.secret_get(args.profile, args.identifier, str(args.project_id) if args.project_id else None)
        elif name == "bitwarden_secret_write_file":
            args = _validate(SecretWriteFileInput, arguments)
            result = service.secret_write_file(args.profile, args.identifier, args.target_path, str(args.project_id) if args.project_id else None)
        elif name == "bitwarden_secret_write_env_file":
            args = _validate(SecretWriteEnvFileInput, arguments)
            result = service.secret_write_env_file(args.profile, args.target_path, args.secrets, str(args.project_id) if args.project_id else None)
        elif name == "bitwarden_secret_create_from_file":
            args = _validate(SecretCreateFromFileInput, arguments)
            result = service.secret_create_from_file(args.profile, str(args.project_id), args.key, args.source_path)
        elif name == "bitwarden_secret_update_from_file":
            args = _validate(SecretUpdateFromFileInput, arguments)
            result = service.secret_update_from_file(args.profile, str(args.project_id), args.identifier, args.source_path)
        elif name == "bitwarden_secret_delete":
            args = _validate(SecretDeleteInput, arguments)
            result = service.secret_delete(args.profile, str(args.project_id), args.identifier, expected_key=args.expected_key)
        elif name == "bitwarden_project_create":
            args = _validate(ProjectCreateInput, arguments)
            result = service.project_create(args.profile, args.name)
        elif name == "bitwarden_project_update":
            args = _validate(ProjectUpdateInput, arguments)
            result = service.project_update(args.profile, str(args.project_id), args.name)
        elif name == "bitwarden_project_delete":
            args = _validate(ProjectDeleteInput, arguments)
            result = service.project_delete(args.profile, str(args.project_id), expected_name=args.expected_name)
        else:
            raise ValueError(f"Unknown tool: {name}")
        return _json_result(result)
    except (ConfigurationError, ProviderError, DeliveryError, SourceError) as exc:
        raise RuntimeError(str(exc)) from exc


async def run_stdio() -> None:
    from mcp.server.stdio import stdio_server

    async with stdio_server() as (read_stream, write_stream):
        await mcp.run(read_stream, write_stream, mcp.create_initialization_options())


def main() -> None:
    configure(Settings.from_env())
    asyncio.run(run_stdio())
