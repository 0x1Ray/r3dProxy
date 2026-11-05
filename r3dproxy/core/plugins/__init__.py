"""Plugin registry: built-ins plus user plugins from ~/.r3dproxy/plugins/."""
from __future__ import annotations
import importlib.util
import traceback
from pathlib import Path
from typing import List

from .base import Plugin, ScanEngine, Finding, Case, MARKER, point_label
from . import builtin
from ...config import CONFIG_DIR

USER_PLUGIN_DIR = CONFIG_DIR / "plugins"


def _load_user_plugins() -> List[Plugin]:
    found = []
    try:
        USER_PLUGIN_DIR.mkdir(parents=True, exist_ok=True)
    except Exception:
        return found
    for path in sorted(USER_PLUGIN_DIR.glob("*.py")):
        if path.name.startswith("_"):
            continue
        try:
            spec = importlib.util.spec_from_file_location(f"r3duserplugin_{path.stem}", path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            if hasattr(mod, "PLUGINS"):
                found.extend(list(mod.PLUGINS))
            elif hasattr(mod, "plugin"):
                found.append(mod.plugin)
        except Exception:
            print(f"[r3dproxy] failed to load user plugin {path.name}:\n{traceback.format_exc()}")
    return found


def get_plugins(include_user=True) -> List[Plugin]:
    plugins = list(builtin.all_plugins())
    if include_user:
        plugins.extend(_load_user_plugins())
    return plugins


def get_plugin(pid: str) -> Plugin:
    for p in get_plugins():
        if p.id == pid:
            return p
    raise KeyError(pid)
