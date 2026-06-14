from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Iterable


HOME = Path.home()


def run_cmd(cmd: list[str], timeout: float = 2.5) -> tuple[int, str, str]:
    try:
        p = subprocess.run(
            cmd,
            text=True,
            capture_output=True,
            timeout=timeout,
            env={**os.environ, "LC_ALL": "C"},
        )
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except FileNotFoundError:
        return 127, "", "command not found"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as exc:                                          
        return 1, "", str(exc)


def command_exists(name: str) -> bool:
    return shutil.which(name) is not None


def first_existing(paths: Iterable[Path]) -> Path | None:
    for path in paths:
        if path.exists():
            return path
    return None


def read_text_safe(path: Path, max_bytes: int = 2_000_000) -> str:
    try:
        with path.open("rb") as f:
            data = f.read(max_bytes)
        return data.decode("utf-8", errors="replace")
    except Exception:
        return ""


def load_json_safe(path: Path) -> dict:
    text = read_text_safe(path)
    if not text:
        return {}
    try:
        return json.loads(text)
    except Exception:
        return {}


def parse_os_release() -> dict[str, str]:
    path = Path("/etc/os-release")
    out: dict[str, str] = {}
    for line in read_text_safe(path).splitlines():
        if "=" not in line or line.startswith("#"):
            continue
        k, v = line.split("=", 1)
        out[k] = v.strip().strip('"')
    return out



def desktop_entries() -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    for root in [Path('/usr/share/applications'), HOME / '.local/share/applications']:
        if not root.exists():
            continue
        for path in root.glob('*.desktop'):
            txt = read_text_safe(path, 80_000)
            if not txt:
                continue
            data: dict[str, str] = {'path': str(path), 'id': path.name.lower()}
            for line in txt.splitlines():
                if not line or line.startswith('#') or '=' not in line:
                    continue
                k, v = line.split('=', 1)
                k = k.strip()
                if k in {'Name', 'GenericName', 'Exec', 'TryExec', 'StartupWMClass', 'NoDisplay'}:
                    data[k] = v.strip()
            entries.append(data)
    return entries


def desktop_app_exists(*needles: str) -> bool:
    needles_l = [n.lower() for n in needles if n]
    for e in desktop_entries():
        hay = ' '.join(e.get(k, '') for k in ['id', 'Name', 'GenericName', 'Exec', 'TryExec', 'StartupWMClass']).lower()
                                                                                            
        if any(n in hay for n in needles_l):
            return True
    return False
