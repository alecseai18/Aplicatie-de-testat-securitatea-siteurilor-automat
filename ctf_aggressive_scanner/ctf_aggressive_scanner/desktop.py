from __future__ import annotations

import os
import platform
import shutil
import subprocess


def _wsl_to_windows_path(path: str) -> str:
    normalized = os.path.abspath(path)
    if normalized.startswith('/mnt/') and len(normalized) > 6:
        drive = normalized[5]
        rest = normalized[7:].replace('/', '\\')
        return f'{drive.upper()}:\\{rest}'
    try:
        completed = subprocess.run(
            ['wslpath', '-w', normalized],
            check=True,
            capture_output=True,
            text=True,
        )
        return completed.stdout.strip() or normalized
    except Exception:
        return normalized


def open_path(path: str) -> None:
    target = os.path.abspath(path)
    if os.name == 'nt':
        os.startfile(target)
        return

    system = platform.system().lower()
    commands: list[list[str]] = []
    if 'microsoft' in platform.release().lower() or os.getenv('WSL_DISTRO_NAME'):
        if shutil.which('wslview'):
            commands.append(['wslview', target])
        if shutil.which('explorer.exe'):
            commands.append(['explorer.exe', _wsl_to_windows_path(target)])
    elif system == 'darwin':
        commands.append(['open', target])

    if shutil.which('xdg-open'):
        commands.append(['xdg-open', target])

    last_error: Exception | None = None
    for command in commands:
        try:
            subprocess.Popen(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return
        except Exception as exc:
            last_error = exc

    detail = f' Last error: {last_error}' if last_error else ''
    raise RuntimeError(f'Could not find a desktop opener for {target}.{detail}')
