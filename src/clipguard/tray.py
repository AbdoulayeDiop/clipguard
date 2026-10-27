"""System tray / menu bar icon (pystray)."""

from __future__ import annotations

import logging
import os
import platform
import subprocess
from typing import TYPE_CHECKING

from . import __version__
from .config import config_dir, write_default_config
from .icon import make_icon

if TYPE_CHECKING:
    from .app import App

log = logging.getLogger("clipguard")


def open_path(path) -> None:
    path = str(path)
    system = platform.system()
    if system == "Windows":
        if path.endswith(".toml"):
            subprocess.Popen(["notepad.exe", path])
        else:
            os.startfile(path)  # type: ignore[attr-defined]
    elif system == "Darwin":
        subprocess.Popen(["open", "-t", path] if path.endswith(".toml") else ["open", path])
    else:
        subprocess.Popen(["xdg-open", path])


class Tray:
    def __init__(self, app: "App") -> None:
        import pystray  # imported here: it needs a display at import time on Linux

        self.app = app
        self._pystray = pystray
        item, menu = pystray.MenuItem, pystray.Menu
        self.icon = pystray.Icon(
            "ClipGuard",
            make_icon(True),
            self._title(),
            menu=menu(
                item(lambda i: f"ClipGuard {__version__}: {self._state()}", None, enabled=False),
                menu.SEPARATOR,
                item("Pause", self._toggle_pause, checked=lambda i: app.paused),
                item("Ask before pasting sensitive data", self._toggle_guard,
                     checked=lambda i: app.paste_guard_on,
                     visible=app.paste_guard_available),
                menu.SEPARATOR,
                item("Edit settings", self._edit_settings),
                item("Reload settings", self._reload),
                item("Open ClipGuard folder", lambda: open_path(config_dir())),
                menu.SEPARATOR,
                item("Quit ClipGuard", self._quit),
            ),
        )

    @property
    def can_notify(self) -> bool:
        return bool(getattr(self.icon, "HAS_NOTIFICATION", False))

    def notify(self, title: str, body: str) -> None:
        self.icon.notify(body, title)

    def _state(self) -> str:
        return "paused" if self.app.paused else "active"

    def _title(self) -> str:
        return f"ClipGuard: {self._state()}"

    def refresh(self) -> None:
        self.icon.icon = make_icon(not self.app.paused)
        self.icon.title = self._title()
        self.icon.update_menu()

    def _toggle_pause(self) -> None:
        self.app.set_paused(not self.app.paused)

    def _toggle_guard(self) -> None:
        self.app.paste_guard_on = not self.app.paste_guard_on
        log.info("paste guard %s", "on" if self.app.paste_guard_on else "off")
        self.refresh()

    def _edit_settings(self) -> None:
        open_path(write_default_config())

    def _reload(self) -> None:
        self.app.reload_config()

    def _quit(self) -> None:
        self.app.quit()

    def run(self) -> None:
        self.icon.run()

    def stop(self) -> None:
        try:
            self.icon.stop()
        except Exception:
            pass
