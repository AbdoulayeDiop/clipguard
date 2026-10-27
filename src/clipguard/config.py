"""User configuration, loaded from a TOML file."""

from __future__ import annotations

import os
import platform
from dataclasses import dataclass, field, fields
from pathlib import Path

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None  # type: ignore

from .detectors import SEVERITY_RANK

DEFAULT_CONFIG = """\
# ClipGuard configuration

# Minimum severity that triggers an alert: "low", "medium" or "high".
# "low" also flags emails and phone numbers.
min_severity = "medium"

# How often to check the clipboard, in seconds.
poll_interval = 0.5

# Clear the clipboard this many seconds after a HIGH severity secret is
# copied (only if it's still on the clipboard). 0 disables auto-clear.
auto_clear_seconds = 0

# Detector ids to switch off, e.g. ["email", "phone", "jwt"].
disabled_detectors = []

# Exact strings that should never trigger an alert (e.g. a test key).
ignore_values = []

# Keep a local log of what kind of data was detected and when.
# The sensitive value itself is never written.
log_detections = true

# Show an icon in the system tray / menu bar (pause, settings, quit).
tray = true

# Windows only: when you press Ctrl+V with sensitive data on the clipboard,
# ask whether to paste a masked version, the original, or nothing.
paste_guard = true
"""


def config_dir() -> Path:
    if platform.system() == "Windows":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    elif platform.system() == "Darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "clipguard"


@dataclass
class Config:
    min_severity: str = "medium"
    poll_interval: float = 0.5
    auto_clear_seconds: float = 0
    disabled_detectors: list[str] = field(default_factory=list)
    ignore_values: list[str] = field(default_factory=list)
    log_detections: bool = True
    tray: bool = True
    paste_guard: bool = True

    def validate(self) -> "Config":
        if self.min_severity not in SEVERITY_RANK:
            raise ValueError(f"min_severity must be one of {list(SEVERITY_RANK)}")
        if self.poll_interval < 0.1:
            raise ValueError("poll_interval must be at least 0.1 seconds")
        if self.auto_clear_seconds < 0:
            raise ValueError("auto_clear_seconds cannot be negative")
        return self


def config_path() -> Path:
    return config_dir() / "config.toml"


def load_config(path: Path | None = None) -> Config:
    path = path or config_path()
    if not path.exists() or tomllib is None:
        return Config().validate()
    with open(path, "rb") as f:
        data = tomllib.load(f)
    known = {f.name for f in fields(Config)}
    unknown = set(data) - known
    if unknown:
        raise ValueError(f"Unknown config keys in {path}: {sorted(unknown)}")
    return Config(**data).validate()


def _toml_value(v) -> str:
    import json
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return f"{v:g}" if isinstance(v, float) else str(v)
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)  # a valid TOML basic string
    if isinstance(v, list):
        return "[" + ", ".join(_toml_value(x) for x in v) + "]"
    raise TypeError(f"unsupported config value {v!r}")


def render_config(cfg: Config) -> str:
    """The commented config.toml for these settings (same layout as DEFAULT_CONFIG)."""
    out = []
    for line in DEFAULT_CONFIG.splitlines():
        key = line.split("=", 1)[0].strip()
        if line and not line.startswith("#") and "=" in line and hasattr(cfg, key):
            out.append(f"{key} = {_toml_value(getattr(cfg, key))}")
        else:
            out.append(line)
    return "\n".join(out) + "\n"


def save_config(cfg: Config, path: Path | None = None) -> Path:
    """Validate and write settings atomically, so a running ClipGuard never reads half a file."""
    cfg.validate()
    path = path or config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".toml.tmp")
    tmp.write_text(render_config(cfg), encoding="utf-8")
    os.replace(tmp, path)
    return path


def write_default_config(path: Path | None = None) -> Path:
    path = path or config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text(DEFAULT_CONFIG, encoding="utf-8")
    return path
