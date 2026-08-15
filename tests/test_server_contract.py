from __future__ import annotations

import asyncio
import json

import pytest

from bitwarden_secrets_manager_mcp import server

EXPECTED_TOOLS = {
    "bitwarden_status",
    "bitwarden_project_list",
    "bitwarden_project_get",
    "bitwarden_secret_list",
    "bitwarden_secret_get",
    "bitwarden_secret_write_file",
    "bitwarden_secret_write_env_file",
    "bitwarden_secret_create_from_file",
    "bitwarden_secret_update_from_file",
    "bitwarden_secret_delete",
    "bitwarden_project_create",
    "bitwarden_project_update",
    "bitwarden_project_delete",
}


def test_server_and_tool_identity_are_new_and_complete() -> None:
    assert server.mcp.name == "bitwarden-secrets-manager"
    tools = asyncio.run(server.list_tools())
    assert {tool.name for tool in tools} == EXPECTED_TOOLS
    assert all(not tool.name.startswith("bws") for tool in tools)


def test_read_only_and_destructive_annotations_are_truthful() -> None:
    tools = {tool.name: tool for tool in asyncio.run(server.list_tools())}
    for name in ("bitwarden_status", "bitwarden_project_list", "bitwarden_project_get", "bitwarden_secret_list", "bitwarden_secret_get"):
        assert tools[name].annotations.readOnlyHint is True
    for name in ("bitwarden_secret_delete", "bitwarden_project_delete"):
        assert tools[name].annotations.readOnlyHint is False
        assert tools[name].annotations.destructiveHint is True
    assert tools["bitwarden_secret_write_file"].annotations.readOnlyHint is False
    assert tools["bitwarden_secret_write_env_file"].annotations.readOnlyHint is False


def test_no_tool_schema_accepts_plaintext_secret_value_or_arbitrary_command() -> None:
    tools = asyncio.run(server.list_tools())
    forbidden = {"value", "secret_value", "command", "argv", "args", "environment"}
    for tool in tools:
        properties = set(tool.inputSchema.get("properties", {}))
        assert not (properties & forbidden), (tool.name, properties & forbidden)
    deletes = {tool.name: tool for tool in tools if tool.name.endswith("_delete")}
    assert deletes["bitwarden_secret_delete"].inputSchema["properties"]["confirm"].get("const") is True
    assert deletes["bitwarden_project_delete"].inputSchema["properties"]["confirm"].get("const") is True


def test_secret_get_description_explicitly_excludes_values() -> None:
    tools = {tool.name: tool for tool in asyncio.run(server.list_tools())}
    description = tools["bitwarden_secret_get"].description.lower()
    assert "metadata" in description
    assert "never" in description and "value" in description


def test_call_tool_returns_json_without_provider_value(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeService:
        def secret_get(self, profile, identifier, project_id=None):
            return {"id": "secret-id", "key": "TOKEN", "profile": profile}

    monkeypatch.setattr(server, "_service", lambda: FakeService())
    content = asyncio.run(server.call_tool("bitwarden_secret_get", {"profile": "test", "identifier": "TOKEN"}))
    payload = json.loads(content[0].text)
    assert payload == {"id": "secret-id", "key": "TOKEN", "profile": "test"}


def test_unknown_tool_fails_closed() -> None:
    with pytest.raises(ValueError, match="Unknown tool"):
        asyncio.run(server.call_tool("sdk_passthrough", {}))
