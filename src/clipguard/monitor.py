"""Clipboard watcher: polls the clipboard and alerts on sensitive content."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from .config import Config, config_dir
from .detectors import HIGH, SEVERITY_RANK, Finding, scan
from .notify import notify

ReadFn = Callable[[], str]
WriteFn = Callable[[str], None]
NotifyFn = Callable[[str, str, bool], object]


def default_clipboard() -> tuple[ReadFn, WriteFn]:
    import pyperclip  # imported lazily so tests don't need a clipboard

    try:
        pyperclip.paste()
    except pyperclip.PyperclipException as e:
        raise SystemExit(
            "ClipGuard can't access the clipboard.\n"
            "On Linux, install xclip or xsel (X11) or wl-clipboard (Wayland).\n"
            f"Details: {e}"
        )
    return pyperclip.paste, pyperclip.copy


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


def format_alert(findings: list[Finding]) -> tuple[str, str]:
    top = findings[0]
    labels = []
    for f in findings:
        if f.label not in labels:
            labels.append(f.label)
    title = "⚠️ Sensitive data copied" if top.severity == HIGH else "Possible sensitive data copied"
    body = ", ".join(labels[:3])
    if len(labels) > 3:
        body += f" +{len(labels) - 3} more"
    body += f" ({top.masked}). Check where you paste it."
    return title, body


@dataclass
class Monitor:
    config: Config
    read: ReadFn
    write: WriteFn
    notifier: NotifyFn = notify
    log_path: Path | None = None
    clock: Callable[[], float] = time.monotonic

    def __post_init__(self) -> None:
        self._last_digest: str | None = None
        self._clear_at: float | None = None
        self._clear_digest: str | None = None
        if self.log_path is None and self.config.log_detections:
            self.log_path = config_dir() / "detections.jsonl"

    def prime(self) -> None:
        """Remember what's already on the clipboard so it isn't flagged at startup."""
        try:
            self._last_digest = _digest(self.read() or "")
        except Exception:
            self._last_digest = None

    def tick(self) -> list[Finding] | None:
        """Check the clipboard once. Returns findings if a new alert fired."""
        try:
            text = self.read() or ""
        except Exception:
            return None

        digest = _digest(text)
        if self._maybe_auto_clear(digest):
            return None

        if digest == self._last_digest:
            return None
        self._last_digest = digest

        if text.strip() in self.config.ignore_values:
            return None

        findings = [
            f for f in scan(text, self.config.min_severity, self.config.disabled_detectors)
            if f.match not in self.config.ignore_values
        ]
        if not findings:
            return None

        title, body = format_alert(findings)
        urgent = findings[0].severity == HIGH
        self.notifier(title, body, urgent)
        self._log(findings)

        if urgent and self.config.auto_clear_seconds > 0:
            self._clear_at = self.clock() + self.config.auto_clear_seconds
            self._clear_digest = digest
        return findings

    def _maybe_auto_clear(self, current_digest: str) -> bool:
        """Clear the clipboard if a pending auto-clear is due. Returns True if cleared."""
        if self._clear_at is None:
            return False
        if current_digest != self._clear_digest:
            self._clear_at = None  # user copied something else; nothing to clear
            return False
        if self.clock() < self._clear_at:
            return False
        self._clear_at = None
        try:
            self.write("")
        except Exception:
            return False
        self._last_digest = _digest("")
        self.notifier("Clipboard cleared",
                      "ClipGuard removed the sensitive item from your clipboard.", False)
        return True

    def _log(self, findings: list[Finding]) -> None:
        if not self.log_path:
            return
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            entry = {
                "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "detectors": sorted({f.detector for f in findings}),
                "max_severity": max((f.severity for f in findings), key=SEVERITY_RANK.get),
            }
            with open(self.log_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry) + "\n")
        except OSError:
            pass

    def run(self) -> None:  # pragma: no cover - infinite loop
        self.prime()
        while True:
            self.tick()
            time.sleep(self.config.poll_interval)
