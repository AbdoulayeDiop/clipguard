"""Start ClipGuard when the user signs in (Windows: HKCU Run key)."""

from __future__ import annotations

import platform
import sys
from pathlib import Path

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
VALUE_NAME = "ClipGuard"


def available() -> bool:
    return platform.system() == "Windows"


def launch_command() -> str:
    """The command Windows should run at sign-in."""
    exe = Path(sys.executable)
    if getattr(sys, "frozen", False):            # PyInstaller build
        return f'"{exe}"'
    pythonw = exe.with_name("pythonw.exe")       # no console window
    return f'"{pythonw if pythonw.exists() else exe}" -m clipguard'


def is_enabled() -> bool:
    if not available():
        return False
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as k:
            winreg.QueryValueEx(k, VALUE_NAME)
            return True
    except OSError:
        return False


def set_enabled(on: bool) -> None:
    if not available():
        return
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as k:
        if on:
            winreg.SetValueEx(k, VALUE_NAME, 0, winreg.REG_SZ, launch_command())
        else:
            try:
                winreg.DeleteValue(k, VALUE_NAME)
            except FileNotFoundError:
                pass
