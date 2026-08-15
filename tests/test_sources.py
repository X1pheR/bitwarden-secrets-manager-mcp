from pathlib import Path
from uuid import UUID

import pytest

from bitwarden_secrets_manager_mcp.config import ProfileSettings
from bitwarden_secrets_manager_mcp.sources import SourceError, read_secret_source


def profile(root: Path) -> ProfileSettings:
    token = root / "token"
    token.write_text("x", encoding="utf-8")
    token.chmod(0o600)
    incoming = root / "incoming"
    incoming.mkdir()
    return ProfileSettings(
        name="test",
        access_token_file=token,
        organization_id=UUID("77dda5e6-1775-4d24-9f28-b4790145d99b"),
        api_url="https://api.bitwarden.eu",
        identity_url="https://identity.bitwarden.eu",
        expected_project_names=("Runtime",),
        allowed_input_directories=(incoming,),
        allowed_output_directories=(),
    )


def test_source_must_be_private_regular_file_under_approved_root(tmp_path: Path) -> None:
    p = profile(tmp_path)
    source = p.allowed_input_directories[0] / "value"
    source.write_text("exact-value\nwith-newline", encoding="utf-8")
    source.chmod(0o600)
    assert read_secret_source(p, str(source)) == "exact-value\nwith-newline"
    source.chmod(0o644)
    with pytest.raises(SourceError, match="private"):
        read_secret_source(p, str(source))


def test_source_rejects_outside_path_and_symlink(tmp_path: Path) -> None:
    p = profile(tmp_path)
    outside = tmp_path / "outside"
    outside.write_text("x", encoding="utf-8")
    outside.chmod(0o600)
    with pytest.raises(SourceError, match="approved input"):
        read_secret_source(p, str(outside))
    link = p.allowed_input_directories[0] / "link"
    link.symlink_to(outside)
    with pytest.raises(SourceError, match="symlink"):
        read_secret_source(p, str(link))
