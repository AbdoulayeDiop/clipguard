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


def write_default_config(path: Path | None = None) -> Path:
    path = path or config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text(DEFAULT_CONFIG, encoding="utf-8")
    return path
