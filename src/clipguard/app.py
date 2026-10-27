"""The ClipGuard application: clipboard watcher + tray icon + paste guard.

Threads:
  * main thread   - tkinter event loop on Windows (dialogs); the tray icon
                    elsewhere (macOS requires the tray on the main thread).
  * watcher       - polls the clipboard and sends copy-time alerts.
  * tray (Win)    - pystray's own message loop.
  * hook (Win)    - low-level keyboard hook that catches Ctrl+V.
Other threads never touch tkinter; they post events to a queue that the
main thread drains.
"""

from __future__ import annotations

import logging
import os
import platform
import queue
import signal
import threading
import time

from .config import Config, load_config
from .detectors import redact, redact_segments
from .monitor import DEFAULT_HINT, GUARD_HINT, Monitor
from .notify import notify as native_notify

log = logging.getLogger("clipguard")
IS_WINDOWS = platform.system() == "Windows"

# Restore the original clipboard this long after pasting a masked version.
RESTORE_DELAY_MS = 800


class App:
    def __init__(self, config: Config, read, write, *,
                 use_tray: bool = True, use_paste_guard: bool = True,
                 config_path=None) -> None:
        self.config = config
        self.config_path = config_path
        self.monitor = Monitor(config, read, write, notifier=self._notify)
        self.use_tray = use_tray and config.tray
        self.paste_guard_available = IS_WINDOWS and use_paste_guard
        self.paste_guard_on = self.paste_guard_available and config.paste_guard
        self.paused = False
        self.tray = None
        self.hook = None
        self.root = None
        self._events: queue.Queue = queue.Queue()
        self._stop = threading.Event()
        self._busy = False
        self._scanned: tuple[int | None, bool] = (None, True)  # (clipboard seq, sensitive?)
        self._allowed_seq: int | None = None
        self._test_choice = os.environ.get("CLIPGUARD_TEST_CHOICE")
        self._update_hint()

    def _update_hint(self) -> None:
        self.monitor.alert_hint = GUARD_HINT if self.paste_guard_on and not self.paused else DEFAULT_HINT

    def set_paste_guard(self, on: bool) -> None:
        self.paste_guard_on = on and self.paste_guard_available
        log.info("paste guard %s", "on" if self.paste_guard_on else "off")
        self._update_hint()
        if self.tray:
            self.tray.refresh()

    # ------------------------------------------------------------------ alerts
    def _notify(self, title: str, body: str, urgent: bool = False) -> None:
        if self.tray is not None and self.tray.can_notify:
            try:
                self.tray.notify(title, body)
                return
            except Exception:
                log.exception("tray notification failed")
        native_notify(title, body, urgent)

    # ----------------------------------------------------------------- control
    def set_paused(self, paused: bool) -> None:
        self.paused = paused
        log.info("paused" if paused else "resumed")
        if not paused:
            self.monitor.prime()  # don't alert for things copied while paused
        self._update_hint()
        if self.tray:
            self.tray.refresh()

    def reload_config(self) -> None:
        try:
            cfg = load_config(self.config_path)
        except Exception as e:
            self._notify("ClipGuard settings error", str(e)[:200])
            return
        self.config = self.monitor.config = cfg
        self.paste_guard_on = self.paste_guard_available and cfg.paste_guard
        self._update_hint()
        self._notify("Settings reloaded", "ClipGuard is using your updated settings.")
        if self.tray:
            self.tray.refresh()

    def quit(self) -> None:
        log.info("quitting")
        self._stop.set()
        if self.hook:
            self.hook.stop()
        if self.tray:
            self.tray.stop()

    # ----------------------------------------------------------------- watcher
    def _watch(self) -> None:
        seq_fn = None
        if IS_WINDOWS:
            from .winapi import clipboard_seq as seq_fn
        self.monitor.prime()
        while not self._stop.is_set():
            if not self.paused:
                try:
                    seq = seq_fn() if seq_fn else None
                    self.monitor.tick()
                    self._scanned = (seq, bool(self.monitor.last_findings))
                except Exception:
                    log.exception("watcher error")
            self._stop.wait(self.config.poll_interval)

    # ------------------------------------------------------------- paste guard
    def _should_block_paste(self, seq: int) -> bool:
        """Called from the keyboard hook: must be fast and never block."""
        if self.paused or not self.paste_guard_on:
            return False
        if seq == self._allowed_seq:
            return False  # user already chose "Paste original" for this content
        scanned_seq, sensitive = self._scanned
        if seq == scanned_seq and not sensitive:
            return False  # clipboard already checked and clean
        return True       # sensitive, or not checked yet: decide on the UI thread

    def _on_paste_blocked(self, hwnd: int, seq: int) -> None:
        self._events.put(("paste", hwnd, seq))

    def _handle_paste(self, hwnd: int, seq: int) -> None:
        from . import winapi
        from .dialog import MASKED, ORIGINAL, ask_paste_choice

        if self._busy:
            return
        self._busy = True
        try:
            text = self.monitor.read() or ""
            findings = self.monitor.findings_for(text)
            if not findings:
                self._scanned = (seq, False)
                self._paste_into(hwnd)
                return

            masked = redact(text, findings)
            log.info("paste paused: %s", ",".join(sorted({f.detector for f in findings})))
            choice = ask_paste_choice(
                self.root, findings, redact_segments(text, findings),
                on_shown=lambda top: winapi.force_foreground(int(top.wm_frame(), 16)),
                auto_choice=self._test_choice,
            )
            log.info("paste choice: %s", choice)

            if choice == MASKED:
                self.monitor.set_clipboard(masked)
                self._paste_into(hwnd)
                self.root.after(RESTORE_DELAY_MS, lambda: self._restore_clipboard(masked, text))
            elif choice == ORIGINAL:
                self._allowed_seq = winapi.clipboard_seq()
                self._paste_into(hwnd)
            else:
                winapi.force_foreground(hwnd)
        except Exception:
            log.exception("paste handling failed")
        finally:
            self._busy = False

    def _paste_into(self, hwnd: int) -> None:
        from . import winapi

        if hwnd and not winapi.force_foreground(hwnd):
            log.warning("could not refocus the target window")
        time.sleep(0.05)
        winapi.send_ctrl_v()

    def _restore_clipboard(self, masked: str, original: str) -> None:
        try:
            if (self.monitor.read() or "") == masked:
                self.monitor.set_clipboard(original)
        except Exception:
            log.exception("could not restore clipboard")

    # -------------------------------------------------------------- main loops
    def _pump(self) -> None:
        while True:
            try:
                kind, *args = self._events.get_nowait()
            except queue.Empty:
                break
            if kind == "paste":
                self._handle_paste(*args)
        if self._stop.is_set():
            self.root.quit()
            return
        self.root.after(30, self._pump)

    def _start_tray(self, in_thread: bool) -> bool:
        if not self.use_tray:
            return False
        try:
            from .tray import Tray
            self.tray = Tray(self)
        except Exception as e:
            log.warning("tray icon unavailable: %s", e)
            self.tray = None
            return False
        if in_thread:
            threading.Thread(target=self.tray.run, name="clipguard-tray", daemon=True).start()
        return True

    def run(self) -> int:
        if IS_WINDOWS:
            from .winapi import already_running
            if already_running():
                native_notify("ClipGuard is already running",
                              "Look for the shield in the taskbar's notification area.")
                return 0

        signal.signal(signal.SIGINT, lambda *a: self.quit())
        threading.Thread(target=self._watch, name="clipguard-watch", daemon=True).start()

        if IS_WINDOWS:
            return self._run_windows()

        # macOS / Linux: the tray icon (if any) owns the main thread.
        if self._start_tray(in_thread=False):
            log.info("tray icon started")
            self.tray.run()
        else:
            while not self._stop.wait(0.5):
                pass
        return 0

    def _run_windows(self) -> int:
        import tkinter as tk
        from .theme import enable_dpi_awareness, load_fonts
        from .winapi import PasteHook

        enable_dpi_awareness()
        load_fonts()
        self.root = tk.Tk()
        self.root.withdraw()
        self._start_tray(in_thread=True)
        if self.paste_guard_available:
            self.hook = PasteHook(
                self._should_block_paste, self._on_paste_blocked,
                allow_injected=os.environ.get("CLIPGUARD_ALLOW_INJECTED") == "1",
            )
            if self.hook.start():
                log.info("paste guard active")
            else:
                self.paste_guard_available = self.paste_guard_on = False
        self.root.after(30, self._pump)
        try:
            self.root.mainloop()
        finally:
            self.quit()
        return 0
