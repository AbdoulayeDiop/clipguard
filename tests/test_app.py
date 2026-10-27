"""Paste-guard decision logic (platform independent: no hook, no GUI)."""

from clipguard.app import App
from clipguard.config import Config
from clipguard.detectors import mask

CARD = "4111 1111 1111 1111"


class Clip:
    def __init__(self, text=""):
        self.text = text

    def read(self):
        return self.text

    def write(self, t):
        self.text = t


def make(initial=""):
    clip = Clip(initial)
    app = App(Config(log_detections=False), clip.read, clip.write, use_tray=False)
    app.paste_guard_on = True  # force on, as on Windows
    app.monitor.notifier = lambda *a: None
    return app, clip


def scan_now(app, seq):
    app.monitor.tick()
    app._scanned = (seq, bool(app.monitor.last_findings))


def test_clean_clipboard_passes_through():
    app, clip = make()
    clip.text = "hello"
    scan_now(app, seq=1)
    assert not app._should_block_paste(1)


def test_sensitive_clipboard_is_blocked():
    app, clip = make()
    clip.text = CARD
    scan_now(app, seq=2)
    assert app._should_block_paste(2)


def test_unscanned_clipboard_is_checked():
    # Copied and pasted before the watcher's next poll: must not slip through.
    app, clip = make()
    clip.text = "hello"
    scan_now(app, seq=1)
    assert app._should_block_paste(2)


def test_sensitive_at_startup_is_known():
    app, clip = make(initial=CARD)
    app.monitor.prime()
    assert app.monitor.last_findings


def test_paste_original_allowed_until_clipboard_changes():
    app, clip = make()
    clip.text = CARD
    scan_now(app, seq=3)
    app._allowed_seq = 3
    assert not app._should_block_paste(3)
    assert app._should_block_paste(4)


def test_paused_or_disabled_never_blocks():
    app, clip = make()
    clip.text = CARD
    scan_now(app, seq=5)
    app.paused = True
    assert not app._should_block_paste(5)
    app.paused, app.paste_guard_on = False, False
    assert not app._should_block_paste(5)


def test_set_clipboard_does_not_alert():
    app, clip = make()
    alerts = []
    app.monitor.notifier = lambda *a: alerts.append(a)
    app.monitor.set_clipboard(CARD)
    app.monitor.tick()
    assert alerts == []


def test_mask_short_secrets_reveal_less():
    assert mask("Tr0ub4dor&3").startswith("Tr…")
    assert "a" not in mask("abcdefgh")
