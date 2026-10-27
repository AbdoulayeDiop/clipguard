"""End-to-end test of the paste guard on a real Windows desktop (runs in CI).

Starts the built executable, copies text, presses Ctrl+V in a test window and
checks what actually lands there. CLIPGUARD_TEST_CHOICE makes the dialog click
"Paste masked" by itself after one second.

Usage: python packaging/e2e_windows.py dist/clipguard.exe
"""

import os
import subprocess
import sys
import tempfile
import time
import tkinter as tk

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import pyperclip  # noqa: E402

from clipguard import winapi  # noqa: E402

exe = sys.argv[1]
appdata = tempfile.mkdtemp()
env = dict(os.environ, APPDATA=appdata,
           CLIPGUARD_ALLOW_INJECTED="1",    # treat our synthetic Ctrl+V as a real one
           CLIPGUARD_TEST_CHOICE="masked")

pyperclip.copy("start")
app = subprocess.Popen([exe, "run"], env=env)

root = tk.Tk()
root.title("ClipGuard e2e target")
root.geometry("520x200+60+60")
box = tk.Text(root)
box.pack(fill="both", expand=True)
failures: list[str] = []


def pump(seconds: float) -> None:
    end = time.time() + seconds
    while time.time() < end:
        root.update()
        time.sleep(0.02)


def check(name: str, ok: bool, detail: str = "") -> None:
    print(("PASS  " if ok else "FAIL  ") + name, detail, flush=True)
    if not ok:
        failures.append(name)


def paste(expect: str, timeout: float = 10) -> str:
    box.delete("1.0", "end")
    root.deiconify()
    root.lift()
    root.update()
    focused = winapi.force_foreground(int(root.wm_frame(), 16))
    box.focus_force()
    root.update()
    print(f"      target focused: {focused}", flush=True)
    winapi.send_ctrl_v(extra=0)
    end = time.time() + timeout
    while time.time() < end:
        pump(0.1)
        if expect in box.get("1.0", "end-1c"):
            break
    return box.get("1.0", "end-1c")


try:
    pump(5)
    check("app is running", app.poll() is None)

    pyperclip.copy("hello world")
    pump(1.5)
    got = paste("hello world")
    check("clean text pastes unchanged", got == "hello world", repr(got))

    secret = "card 4111 1111 1111 1111"
    pyperclip.copy(secret)
    pump(1.5)
    got = paste("1111")
    check("sensitive text pastes masked", got == "card **** **** **** 1111", repr(got))
    pump(2)
    now = pyperclip.paste()
    check("original clipboard restored", now == secret, repr(now))

    pyperclip.copy("pin 5555 5555 5555 4444")  # paste before the watcher polls
    got = paste("4444")
    check("instant paste is masked too", got == "pin **** **** **** 4444", repr(got))

    check("app still running", app.poll() is None)

    settings = subprocess.Popen([exe, "settings"], env=env)
    pump(4)
    check("settings window starts", settings.poll() is None)
    settings.terminate()
finally:
    app.terminate()
    try:
        app.wait(5)
    except subprocess.TimeoutExpired:
        app.kill()
    log = os.path.join(appdata, "clipguard", "clipguard.log")
    print("\n--- clipguard.log ---")
    print(open(log, encoding="utf-8").read() if os.path.exists(log) else "(no log)")

if failures:
    print(f"\n{len(failures)} check(s) failed: {failures}")
    sys.exit(1)
print("\nAll paste-guard checks passed.")
