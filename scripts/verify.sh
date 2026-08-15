#!/usr/bin/env bash
set -euo pipefail

command -v uv >/dev/null 2>&1 || { echo "uv is required to verify this repository" >&2; exit 1; }

work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

uv sync --frozen --extra test
PYTHONPATH=src PYTHONPYCACHEPREFIX="$work_dir/pycache" uv run --frozen --extra test python -m compileall -q src tests
PYTHONPATH=src uv run --frozen --extra test pytest -p no:cacheprovider

python3 - <<'PY'
from pathlib import Path
source = "\n".join(path.read_text(encoding="utf-8") for path in Path("src").rglob("*.py"))
for forbidden in ("subprocess", "BWS_BIN", "bws-secrets-mcp", "bws_secrets_mcp", "bws-secrets"):
    if forbidden in source:
        raise SystemExit(f"forbidden provider/legacy source marker: {forbidden}")
PY

export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git show -s --format=%ct HEAD 2>/dev/null || date +%s)}"
uv build --out-dir "$work_dir/build"
wheel="$(find "$work_dir/build" -maxdepth 1 -type f -name '*.whl' -print -quit)"
sdist="$(find "$work_dir/build" -maxdepth 1 -type f -name '*.tar.gz' -print -quit)"
test -n "$wheel" && test -n "$sdist"

uv venv --python 3.12 "$work_dir/install" >/dev/null
uv pip install --python "$work_dir/install/bin/python" "$wheel" >/dev/null
"$work_dir/install/bin/python" - <<'PY'
import importlib.metadata
import bitwarden_secrets_manager_mcp
assert importlib.metadata.version("bitwarden-secrets-manager-mcp") == "0.1.0"
assert callable(bitwarden_secrets_manager_mcp.main)
PY
