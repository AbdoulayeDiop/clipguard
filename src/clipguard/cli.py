"""Command-line entry point."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from . import __version__
from .config import config_path, load_config, write_default_config
from .detectors import PATTERNS, SEVERITY_RANK, scan
from .notify import notify


def _setup_logging() -> None:
    from logging.handlers import RotatingFileHandler

    from .config import config_dir

    logger = logging.getLogger("clipguard")
    logger.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    try:
        config_dir().mkdir(parents=True, exist_ok=True)
        fh = RotatingFileHandler(config_dir() / "clipguard.log", maxBytes=1_000_000,
                                 backupCount=1, encoding="utf-8")
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    except OSError:
        pass
    if sys.stderr and getattr(sys.stderr, "isatty", lambda: False)():
        sh = logging.StreamHandler()
        sh.setFormatter(fmt)
        logger.addHandler(sh)


def _cmd_run(args: argparse.Namespace) -> int:
    from .app import App
    from .monitor import default_clipboard

    _setup_logging()
    path = Path(args.config) if args.config else None
    try:
        cfg = load_config(path)
        if args.min_severity:
            cfg.min_severity = args.min_severity
        if args.auto_clear is not None:
            cfg.auto_clear_seconds = args.auto_clear
        cfg.validate()
    except Exception as e:  # visible even in the no-console build
        notify("ClipGuard settings error", str(e)[:200])
        print(f"Settings error: {e}", file=sys.stderr)
        return 2

    read, write = default_clipboard()
    print(f"ClipGuard {__version__} is watching your clipboard "
          f"(alerts at '{cfg.min_severity}' and above). Press Ctrl+C to stop.")
    logging.getLogger("clipguard").info("started v%s", __version__)
    App(cfg, read, write, use_tray=not args.no_tray,
        use_paste_guard=not args.no_paste_guard, config_path=path).run()
    print("ClipGuard stopped.")
    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    text = sys.stdin.read() if args.file == "-" else Path(args.file).read_text(
        encoding="utf-8", errors="replace")
    findings = scan(text, args.min_severity or "low")
    if not findings:
        print("No sensitive data found.")
        return 0
    for f in findings:
        print(f"[{f.severity.upper():6}] {f.label:38} {f.masked}")
    return 1


def _cmd_detectors(_: argparse.Namespace) -> int:
    for p in PATTERNS:
        print(f"{p.id:22} {p.severity:7} {p.label}")
    print(f"{'high_entropy':22} {'medium':7} Password or secret (high entropy)")
    return 0


def _cmd_config(_: argparse.Namespace) -> int:
    print(write_default_config())
    return 0


def _cmd_test(_: argparse.Namespace) -> int:
    shown = notify("ClipGuard test", "Notifications are working.", False)
    print("Notification sent." if shown else "No native notifier found; printed to terminal instead.")
    return 0


def _ensure_streams() -> None:
    """Windowed builds (no console) have sys.stdout/stderr set to None."""
    import os
    for name in ("stdout", "stderr"):
        if getattr(sys, name) is None:
            setattr(sys, name, open(os.devnull, "w", encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    _ensure_streams()
    parser = argparse.ArgumentParser(
        prog="clipguard",
        description="Get an alert when you copy passwords, API keys, card numbers "
                    "or other sensitive data.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")

    run = sub.add_parser("run", help="watch the clipboard (default)")
    run.add_argument("--config", help=f"config file (default: {config_path()})")
    run.add_argument("--min-severity", choices=list(SEVERITY_RANK))
    run.add_argument("--auto-clear", type=float, metavar="SECONDS",
                     help="clear high-severity secrets from the clipboard after N seconds")
    run.add_argument("--no-tray", action="store_true", help="don't show the tray icon")
    run.add_argument("--no-paste-guard", action="store_true",
                     help="don't intercept Ctrl+V (Windows)")
    run.set_defaults(func=_cmd_run)

    sc = sub.add_parser("scan", help="scan a file or stdin ('-') and print findings")
    sc.add_argument("file")
    sc.add_argument("--min-severity", choices=list(SEVERITY_RANK))
    sc.set_defaults(func=_cmd_scan)

    sub.add_parser("detectors", help="list detectors").set_defaults(func=_cmd_detectors)
    sub.add_parser("init-config", help="create a default config file").set_defaults(func=_cmd_config)
    sub.add_parser("test-notify", help="send a test notification").set_defaults(func=_cmd_test)

    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        args = parser.parse_args(["run", *(argv or [])])
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
