"""Minimal .env loading without external dependencies."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Iterable

_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def project_env_paths() -> list[Path]:
    """Return candidate .env files in load order."""
    project_root = Path(__file__).resolve().parent.parent
    paths = [project_root / ".env"]
    try:
        cwd_env = Path.cwd() / ".env"
    except OSError:
        return paths
    if cwd_env.resolve() != paths[0].resolve():
        paths.append(cwd_env)
    return paths


def load_dotenv(
    paths: Iterable[str | os.PathLike[str]] | None = None,
    *,
    override: bool = False,
) -> list[Path]:
    """Load KEY=VALUE pairs from .env files into the process environment.

    Existing environment variables win unless ``override`` is true. Missing
    files and malformed lines are ignored so a partial .env is still useful.
    """
    candidates = [Path(path) for path in paths] if paths is not None else project_env_paths()
    loaded: list[Path] = []
    for path in candidates:
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        loaded.append(path)
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[len("export ") :].strip()
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            if not _KEY.match(key):
                continue
            value = _parse_value(value.strip())
            if override or key not in os.environ:
                os.environ[key] = value
    return loaded


def set_env_value(
    path: str | os.PathLike[str], key: str, value: str
) -> Path:
    """Set one KEY=VALUE pair in a .env file, preserving other lines."""
    if not isinstance(key, str) or not _KEY.match(key):
        raise ValueError(f"invalid environment key: {key!r}")
    if not isinstance(value, str) or not value:
        raise ValueError("environment value must be a non-empty string")
    target = Path(path)
    lines: list[str] = []
    if target.exists():
        lines = target.read_text(encoding="utf-8").splitlines()
    pattern = re.compile(rf"^\s*(?:export\s+)?{re.escape(key)}\s*=")
    replaced = False
    for index, line in enumerate(lines):
        if pattern.match(line):
            lines[index] = f"{key}={value}"
            replaced = True
    if not replaced:
        lines.append(f"{key}={value}")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return target


def _parse_value(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    if " #" in value:
        value = value.split(" #", 1)[0].rstrip()
    return value
