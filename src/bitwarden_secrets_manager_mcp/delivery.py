from __future__ import annotations

import os
import re
import stat
import tempfile
from pathlib import Path
from typing import Mapping

from .config import ProfileSettings


class DeliveryError(RuntimeError):
    """Raised when a protected file delivery cannot be performed safely."""


_ENV_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _validate_target(profile: ProfileSettings, target_path: str) -> tuple[Path, os.stat_result | None]:
    target = Path(target_path)
    if not target.is_absolute():
        raise DeliveryError("Target path must be absolute")
    try:
        target_info = target.lstat()
    except FileNotFoundError:
        target_info = None
    if target_info is not None and stat.S_ISLNK(target_info.st_mode):
        raise DeliveryError("Target path must not be a symlink")
    if target_info is not None and not stat.S_ISREG(target_info.st_mode):
        raise DeliveryError("Target path must be a regular file when it already exists")
    try:
        parent = target.parent.resolve(strict=True)
    except FileNotFoundError as exc:
        raise DeliveryError("Target parent directory does not exist") from exc
    if not parent.is_dir():
        raise DeliveryError("Target parent must be a directory")
    approved = False
    for configured_root in profile.allowed_output_directories:
        try:
            root = configured_root.resolve(strict=True)
        except FileNotFoundError:
            continue
        if _within(parent, root):
            approved = True
            break
    if not approved:
        raise DeliveryError("Target path is outside every approved output directory")
    return target, target_info


def atomic_write(profile: ProfileSettings, target_path: str, payload: bytes) -> Path:
    target, existing = _validate_target(profile, target_path)
    mode = stat.S_IMODE(existing.st_mode) if existing is not None else profile.file_mode
    uid = existing.st_uid if existing is not None else None
    gid = existing.st_gid if existing is not None else None
    fd, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=str(target.parent))
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
            os.fchmod(handle.fileno(), mode)
            if uid is not None and gid is not None:
                os.fchown(handle.fileno(), uid, gid)
        os.replace(temporary, target)
        directory_fd = os.open(target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError as exc:
        raise DeliveryError("Atomic secret delivery failed") from exc
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return target


def env_payload(values: Mapping[str, str]) -> bytes:
    lines: list[str] = []
    for key in sorted(values):
        if _ENV_KEY.fullmatch(key) is None:
            raise DeliveryError(f"Invalid environment variable name: {key}")
        value = values[key]
        if "\x00" in value:
            raise DeliveryError(f"Secret value for {key} contains NUL and cannot be written as raw env")
        if "\r" in value or "\n" in value:
            raise DeliveryError(f"Secret value for {key} contains a newline and cannot be written as raw env")
        lines.append(f"{key}={value}\n")
    return "".join(lines).encode("utf-8")
