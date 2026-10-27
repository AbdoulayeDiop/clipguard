"""Settings: saving/loading round trip and the window's state model (no GUI)."""

from clipguard.config import Config, load_config, render_config, save_config
from clipguard.settings import SettingsState, clear_choices, detector_catalog


def test_save_load_round_trip(tmp_path):
    cfg = Config(min_severity="high", auto_clear_seconds=60, disabled_detectors=["email", "jwt"],
                 ignore_values=['quote " and \\ backslash', "émoji ✓"], log_detections=False,
                 paste_guard=False)
    path = save_config(cfg, tmp_path / "config.toml")
    assert load_config(path) == cfg


def test_rendered_file_keeps_comments():
    text = render_config(Config())
    assert text.startswith("# ClipGuard configuration")
    assert 'min_severity = "medium"' in text and "paste_guard = true" in text


def test_save_rejects_invalid(tmp_path):
    import pytest
    with pytest.raises(ValueError):
        save_config(Config(min_severity="extreme"), tmp_path / "c.toml")
    assert not (tmp_path / "c.toml").exists()


def test_state_toggles_detectors_and_keeps_unknown_ids():
    s = SettingsState(Config(disabled_detectors=["email", "from_a_newer_version"]))
    s.disabled.discard("email")
    s.disabled.add("jwt")
    cfg = s.to_config()
    assert cfg.disabled_detectors == ["from_a_newer_version", "jwt"]


def test_state_ignore_values_dedupe_and_trim():
    s = SettingsState(Config())
    value = "test-" + "x" * 10
    assert s.add_ignore(f"  {value} ")
    assert not s.add_ignore(value)
    assert not s.add_ignore("   ")
    assert s.to_config().ignore_values == [value]


def test_state_preserves_settings_not_in_window():
    s = SettingsState(Config(poll_interval=1.5, tray=False))
    s.min_severity = "low"
    cfg = s.to_config()
    assert cfg.poll_interval == 1.5 and cfg.tray is False and cfg.min_severity == "low"


def test_catalog_covers_every_detector_once():
    ids = [d for d, _, _ in detector_catalog()]
    assert len(ids) == len(set(ids)) and "high_entropy" in ids and "credit_card" in ids


def test_custom_clear_value_is_offered():
    assert (45, "45 s") in clear_choices(45)
    assert len(clear_choices(30)) == 4
