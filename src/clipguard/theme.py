"""ClipGuard design tokens for the desktop app.

Mirrors tokens.json in the ClipGuard design system, value for value, in both
themes. tkinter can't read CSS, so when a token changes there, change it here.
"""

from __future__ import annotations

import logging
import os
import platform
from pathlib import Path

log = logging.getLogger("clipguard")

COLORS = {
    "light": {
        "surface": "#f2f4f1", "surface-raised": "#ffffff", "surface-sunken": "#e8ece8",
        "line": "#d5dcd7", "line-strong": "#7e8b86",
        "ink": "#14211f", "ink-muted": "#4c5a56", "neutral-tint": "#e6ebe8",
        "guard": "#0b6b57", "guard-strong": "#08513f", "on-guard": "#ffffff", "guard-tint": "#dbefe8",
        "hold": "#8a5300", "hold-mark": "#c77a0a", "hold-tint": "#fcefd8",
        "alert": "#b42318", "alert-tint": "#fde6e2",
        "redact": "#17241f", "focus": "#0b6b57",
    },
    "dark": {
        "surface": "#0e1615", "surface-raised": "#162120", "surface-sunken": "#0a100f",
        "line": "#2a3735", "line-strong": "#6b7a76",
        "ink": "#e3eae7", "ink-muted": "#a1afaa", "neutral-tint": "#22302d",
        "guard": "#46c6a1", "guard-strong": "#7fdcbf", "on-guard": "#03211a", "guard-tint": "#123a31",
        "hold": "#f3b04c", "hold-mark": "#f3b04c", "hold-tint": "#3a2a10",
        "alert": "#ff8c7c", "alert-tint": "#3e1915",
        "redact": "#c3cfca", "focus": "#7fdcbf",
    },
}

SPACE = {1: 4, 2: 8, 3: 12, 4: 16, 6: 24, 8: 32}
RADIUS = {"bar": 2, "sm": 4, "md": 6, "lg": 10}

SANS = "Atkinson Hyperlegible Next"
MONO = "Atkinson Hyperlegible Mono"
FALLBACK = {
    "Windows": ("Segoe UI", "Consolas"),
    "Darwin": ("Helvetica Neue", "Menlo"),
}.get(platform.system(), ("DejaVu Sans", "DejaVu Sans Mono"))

# Type styles: (family role, size px, weight)
TYPE = {
    "title": ("sans", 18, "bold"),
    "body": ("sans", 14, "normal"),
    "body-strong": ("sans", 14, "bold"),
    "caption": ("sans", 12, "normal"),
    "eyebrow": ("sans", 11, "bold"),
    "value": ("mono", 13, "normal"),
    "value-small": ("mono", 12, "normal"),
    "tag": ("mono", 10, "bold"),
}

FONT_DIR = Path(__file__).with_name("fonts")


def _registry_light(value_name: str) -> bool | None:
    if platform.system() != "Windows":
        return None
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize") as k:
            return bool(winreg.QueryValueEx(k, value_name)[0])
    except OSError:
        return None


def app_theme() -> str:
    """'light' or 'dark' for windows, following the OS app setting."""
    forced = os.environ.get("CLIPGUARD_THEME")
    if forced in COLORS:
        return forced
    light = _registry_light("AppsUseLightTheme")
    return "dark" if light is False else "light"


def taskbar_theme() -> str:
    """'light' or 'dark' for the tray icon, following the taskbar."""
    forced = os.environ.get("CLIPGUARD_THEME")
    if forced in COLORS:
        return forced
    light = _registry_light("SystemUsesLightTheme")
    if light is None:
        return "light" if platform.system() != "Windows" else "dark"
    return "light" if light else "dark"


_fonts_loaded = False


def load_fonts() -> None:
    """Make the bundled fonts available to this process (Windows)."""
    global _fonts_loaded
    if _fonts_loaded or platform.system() != "Windows":
        return
    _fonts_loaded = True
    import ctypes
    FR_PRIVATE = 0x10
    for f in sorted(FONT_DIR.glob("*.ttf")):
        if not ctypes.windll.gdi32.AddFontResourceExW(str(f), FR_PRIVATE, 0):
            log.warning("could not load font %s", f.name)


def enable_dpi_awareness() -> None:
    if platform.system() != "Windows":
        return
    import ctypes
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)  # system DPI aware: crisp text
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass


class Theme:
    """Resolved tokens for one tkinter root: colours, pixel scale and fonts."""

    def __init__(self, root, name: str | None = None) -> None:
        import tkinter.font as tkfont

        self.name = name or app_theme()
        self.c = COLORS[self.name]
        self.scale = max(1.0, root.winfo_fpixels("1i") / 96.0)
        families = set(tkfont.families(root))
        self.sans = SANS if SANS in families else FALLBACK[0]
        self.mono = MONO if MONO in families else FALLBACK[1]
        self.fonts = {}
        for style, (role, size, weight) in TYPE.items():
            family = self.sans if role == "sans" else self.mono
            self.fonts[style] = tkfont.Font(root=root, family=family, size=-self.px(size), weight=weight)

    def px(self, n: float) -> int:
        return int(round(n * self.scale))

    def space(self, step: int) -> int:
        return self.px(SPACE[step])
