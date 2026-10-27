from clipguard.config import Config
from clipguard.monitor import Monitor


class FakeClipboard:
    def __init__(self, text=""):
        self.text = text

    def read(self):
        return self.text

    def write(self, text):
        self.text = text


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def make(cfg=None, initial=""):
    clip, alerts, clock = FakeClipboard(initial), [], FakeClock()
    m = Monitor(cfg or Config(log_detections=False), clip.read, clip.write,
                notifier=lambda t, b, u: alerts.append((t, b, u)), clock=clock)
    m.prime()
    return m, clip, alerts, clock


CARD = "4111 1111 1111 1111"


def test_alerts_once_per_copy():
    m, clip, alerts, _ = make()
    clip.text = CARD
    m.tick(); m.tick(); m.tick()
    assert len(alerts) == 1
    assert "Credit card" in alerts[0][1]
    assert CARD not in alerts[0][1]  # never show the raw value


def test_existing_clipboard_not_flagged_at_startup():
    m, clip, alerts, _ = make(initial=CARD)
    m.tick()
    assert alerts == []


def test_harmless_text_no_alert():
    m, clip, alerts, _ = make()
    clip.text = "just some notes"
    m.tick()
    assert alerts == []


def test_ignore_values():
    m, clip, alerts, _ = make(Config(log_detections=False, ignore_values=[CARD]))
    clip.text = CARD
    m.tick()
    assert alerts == []


def test_auto_clear():
    m, clip, alerts, clock = make(Config(log_detections=False, auto_clear_seconds=30))
    clip.text = CARD
    m.tick()
    clock.t = 10; m.tick()
    assert clip.text == CARD
    clock.t = 31; m.tick()
    assert clip.text == ""
    assert alerts[-1][0] == "Clipboard cleared"


def test_auto_clear_skipped_if_user_copied_something_else():
    m, clip, alerts, clock = make(Config(log_detections=False, auto_clear_seconds=30))
    clip.text = CARD
    m.tick()
    clip.text = "something else"
    m.tick()
    clock.t = 60; m.tick()
    assert clip.text == "something else"


def test_log_never_contains_secret(tmp_path):
    log = tmp_path / "log.jsonl"
    clip, alerts = FakeClipboard(), []
    m = Monitor(Config(), clip.read, clip.write,
                notifier=lambda *a: alerts.append(a), log_path=log)
    m.prime()
    clip.text = CARD
    m.tick()
    content = log.read_text()
    assert "credit_card" in content and "4111" not in content
