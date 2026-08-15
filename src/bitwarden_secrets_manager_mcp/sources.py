from __future__ import annotations

import os
import stat
from pathlib import Path

from .config import ProfileSettings


class SourceError(ValueError):
    """Raised when a secret source file violates the protected-import boundary."""


_MAX_SOURCE_BYTES = 1024 * 1024


def _within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _approved_source(profile: ProfileSettings, source_path: str) -> Path:
    source = Path(source_path)
    if not source.is_absolute():
        raise SourceError("Secret source path must be absolute")
    try:
        info = source.lstat()
    except FileNotFoundError as exc:
        raise SourceError("Secret source file does not exist") from exc
    if stat.S_ISLNK(info.st_mode):
        raise SourceError("Secret source file must not be a symlink")
    if not stat.S_ISREG(info.st_mode):
        raise SourceError("Secret source must be a regular file")
    try:
        parent = source.parent.resolve(strict=True)
    except FileNotFoundError as exc:
        raise SourceError("Secret source parent does not exist") from exc
    approved = False
    for configured_root in profile.allowed_input_directories:
        try:
            root = configured_root.resolve(strict=True)
        except FileNotFoundError:
            continue
        if _within(parent, root):
            approved = True
            break
    if not approved:
        raise SourceError("Secret source is outside every approved input directory")
    return source


def read_secret_source(profile: ProfileSettings, source_path: str) -> str:
    source = _approved_source(profile, source_path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(source, flags)
    except OSError as exc:
        raise SourceError("Secret source file could not be opened safely") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise SourceError("Secret source must remain a regular file")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise SourceError("Secret source file must be private (0600 or stricter)")
        if info.st_size > _MAX_SOURCE_BYTES:
            raise SourceError("Secret source file exceeds the 1 MiB safety limit")
        with os.fdopen(fd, "r", encoding="utf-8", closefd=False) as handle:
            try:
                return handle.read()
            except UnicodeDecodeError as exc:
                raise SourceError("Secret source file must contain UTF-8 text") from exc
    finally:
        os.close(fd)
