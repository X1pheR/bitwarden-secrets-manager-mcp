from pathlib import Path

import pytest

from bitwarden_secrets_manager_mcp.config import ProfileSettings
from bitwarden_secrets_manager_mcp.delivery import DeliveryError, atomic_write, env_payload


def profile(root: Path) -> ProfileSettings:
    token = root / "token"
    token.write_text("x", encoding="utf-8")
    token.chmod(0o600)
    output = root / "output"
    output.mkdir()
    return ProfileSettings(
        name="test",
        access_token_file=token,
        organization_id=__import__("uuid").UUID("77dda5e6-1775-4d24-9f28-b4790145d99b"),
        api_url="https://api.bitwarden.eu",
        identity_url="https://identity.bitwarden.eu",
        expected_project_names=("Runtime",),
        allowed_input_directories=(),
        allowed_output_directories=(output,),
        file_mode=0o640,
    )


def test_atomic_write_is_bounded_and_uses_profile_mode(tmp_path: Path) -> None:
    p = profile(tmp_path)
    target = p.allowed_output_directories[0] / "secret.txt"
    atomic_write(p, str(target), b"secret-bytes")
    assert target.read_bytes() == b"secret-bytes"
    assert target.stat().st_mode & 0o777 == 0o640
    with pytest.raises(DeliveryError, match="approved output"):
        atomic_write(p, str(tmp_path / "outside"), b"nope")


def test_atomic_write_rejects_symlink_target(tmp_path: Path) -> None:
    p = profile(tmp_path)
    real = p.allowed_output_directories[0] / "real"
    real.write_text("old", encoding="utf-8")
    target = p.allowed_output_directories[0] / "link"
    target.symlink_to(real)
    with pytest.raises(DeliveryError, match="symlink"):
        atomic_write(p, str(target), b"new")


def test_env_payload_is_complete_raw_env_and_rejects_unsafe_values() -> None:
    assert env_payload({"BETA": "two=2", "ALPHA": "one"}) == b"ALPHA=one\nBETA=two=2\n"
    with pytest.raises(DeliveryError, match="environment variable"):
        env_payload({"bad-key": "value"})
    with pytest.raises(DeliveryError, match="newline"):
        env_payload({"TOKEN": "a\nb"})
    with pytest.raises(DeliveryError, match="NUL"):
        env_payload({"TOKEN": "a\x00b"})
