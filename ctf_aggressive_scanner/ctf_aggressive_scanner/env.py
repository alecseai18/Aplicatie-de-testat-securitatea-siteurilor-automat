from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Iterable


ENV_FILES = ('.env.local', '.env')
_LOADED_ROOTS: set[Path] = set()


def _candidate_roots(root: str | os.PathLike[str] | None = None) -> Iterable[Path]:
    if root is not None:
        yield Path(root).resolve()
        return

    yield Path.cwd().resolve()
    yield Path(__file__).resolve().parent.parent


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
        return value[1:-1]
    return value


def _load_env_file(path: Path) -> None:
    if not path.is_file():
        return

    for raw_line in path.read_text(encoding='utf-8').splitlines():
        line = raw_line.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('export '):
            line = line[7:].lstrip()
        if '=' not in line:
            continue

        key, value = line.split('=', 1)
        key = key.strip()
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', key):
            continue
        if key not in os.environ:
            os.environ[key] = _unquote(value)


def load_local_env(root: str | os.PathLike[str] | None = None) -> None:
    """Load local env files without overriding variables already set by the shell."""
    for candidate in _candidate_roots(root):
        if candidate in _LOADED_ROOTS:
            continue
        for filename in ENV_FILES:
            _load_env_file(candidate / filename)
        _LOADED_ROOTS.add(candidate)


def get_gemini_api_key(explicit: str = '') -> str:
    load_local_env()
    return (explicit or os.getenv('GEMINI_API_KEY') or os.getenv('GOOGLE_API_KEY') or '').strip()
