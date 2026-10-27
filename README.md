# ClipGuard

A small background app that warns you when you copy something sensitive (a password, API key, card number, IBAN, private key) so you think twice before pasting it into a chat, an AI tool or the wrong window.

Works on macOS, Windows and Linux. Everything runs locally: nothing is sent anywhere, and the sensitive value is never written to disk or shown in full in notifications.

On Windows it can also **stop the paste itself**: press Ctrl+V with a secret on the clipboard and ClipGuard asks whether to paste a masked version instead.

![Paste guard dialog](docs/paste-dialog.png)

## Tray icon

While ClipGuard runs, a shield sits in the notification area of the taskbar (on Windows, click the **^** arrow if it's hidden; drag it onto the taskbar to keep it visible). Green means active, grey means paused. Right-click it for:

- **Pause:** stop watching temporarily.
- **Ask before pasting sensitive data** (Windows): turn the paste guard on or off.
- **Edit settings** / **Reload settings:** open `config.toml`, then apply your changes without restarting.
- **Open ClipGuard folder:** settings, `clipguard.log` and `detections.jsonl`.
- **Quit ClipGuard.**

## Paste guard (Windows)

When the clipboard holds something sensitive and you press **Ctrl+V** (or Ctrl+Shift+V), ClipGuard holds the paste and shows what it found, plus a preview of the masked text. You can then choose:

| Button | What gets pasted |
|---|---|
| **Paste masked** (Enter) | The text with secrets replaced: `**** **** **** 1111`, `postgres://admin:********@host`, `[PRIVATE KEY REDACTED]`… Your clipboard keeps the original afterwards. |
| **Paste original** | The text as copied. ClipGuard won't ask again until you copy something else. |
| **Cancel** (Esc) | Nothing. |

Clean text pastes instantly with no dialog. The check also covers text you paste right after copying, before the watcher's next poll.

Not covered: pasting through a right-click menu or Edit → Paste (only the keyboard shortcut is intercepted), and automatic typing by other software such as a password manager's auto-type, which is deliberately left alone. On macOS and Linux you get the copy-time notification only.

## What it detects

| Severity | Examples |
|---|---|
| High | AWS, GitHub, GitLab, OpenAI, Anthropic, Google, Stripe, Slack, Twilio, SendGrid, npm and Hugging Face keys; private keys; database URLs with passwords; `password=…` lines; credit card numbers (Luhn-checked); US SSNs; French NIR numbers |
| Medium | IBANs (mod-97 checked), JWTs, Slack webhooks, high-entropy strings that look like passwords |
| Low | Email addresses, phone numbers |

By default, alerts fire at **medium** and above. Run `clipguard detectors` for the full list, or read [how the detectors work](docs/detectors.md).

## Download (no Python needed)

Grab the file for your system from the [latest release](https://github.com/AbdoulayeDiop/clipguard/releases/latest):

| System | File |
|---|---|
| Windows: runs silently in the background | `clipguard-background-windows-x64.exe` |
| Windows: shows a console window | `clipguard-windows-x64.exe` |
| macOS (Apple Silicon) | `clipguard-macos-arm64` |
| Linux | `clipguard-linux-x64` |

Double-click to start: the shield appears in the taskbar's notification area, and you quit from its right-click menu. Starting it a second time does nothing, because only one copy runs at a time. To start it at login, press Win+R, type `shell:startup`, and put a shortcut to the `.exe` in that folder.

Windows SmartScreen may warn the first time because the file isn't code-signed: click **More info → Run anyway**. On macOS, run `chmod +x clipguard-macos-arm64`, then right-click → Open the first time.

## Install with pip

Requires Python 3.11+.

```bash
pip install git+https://github.com/AbdoulayeDiop/clipguard.git
```

Linux also needs a clipboard tool and a notifier:

```bash
sudo apt install xclip libnotify-bin      # X11
sudo apt install wl-clipboard libnotify-bin  # Wayland
```

## Use

```bash
clipguard                     # start watching the clipboard
clipguard test-notify         # check that notifications show up
clipguard scan notes.txt      # scan a file (or "-" for stdin)
clipguard init-config         # create a config file and print its path
```

Options for `clipguard run`:

- `--min-severity low|medium|high`: alert threshold
- `--auto-clear 30`: wipe high-severity secrets from the clipboard after 30 seconds (only if you haven't copied something else since)
- `--no-tray`: run without the tray icon
- `--no-paste-guard`: don't intercept Ctrl+V

## Configure

`clipguard init-config` creates a commented `config.toml`:

- macOS: `~/Library/Application Support/clipguard/`
- Windows: `%APPDATA%\clipguard\`
- Linux: `~/.config/clipguard/`

```toml
min_severity = "medium"
poll_interval = 0.5
auto_clear_seconds = 0
disabled_detectors = ["jwt"]
ignore_values = ["my-public-test-key"]
log_detections = true
tray = true
paste_guard = true        # Windows
```

If logging is on, `detections.jsonl` in the same folder records *what kind* of data was detected and when, never the value.

## Start automatically at login

**macOS:** save as `~/Library/LaunchAgents/com.clipguard.plist`, then run `launchctl load ~/Library/LaunchAgents/com.clipguard.plist`.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.clipguard</string>
  <key>ProgramArguments</key><array><string>/usr/local/bin/clipguard</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict></plist>
```

Use `which clipguard` to get the right path.

**Windows:** press Win+R, type `shell:startup`, and add a shortcut to `pythonw -m clipguard`.

**Linux:** copy `contrib/clipguard.desktop` to `~/.config/autostart/`.

## Limitations

- The paste guard is Windows-only, and only catches the keyboard shortcut (see above).
- Detection is pattern-based. It will miss some secrets and occasionally flag harmless text; use `ignore_values` and `disabled_detectors` to tune it.
- On macOS the first notification may ask for permission for "Script Editor" (used to show notifications).

## Development

```bash
pip install -e ".[dev]"
pytest
```

Test secrets are assembled at runtime so no real-looking token appears in the source.

`packaging/e2e_windows.py` is an end-to-end test of the paste guard. CI runs it on Windows against the built `.exe`: it copies text, presses Ctrl+V in a test window and checks what gets pasted.

## Roadmap

- Paste guard on macOS
- Only guard pastes into specific apps (browsers, chat apps)
- Per-app allowlist (e.g. don't alert when copying from your password manager)
- Custom regex detectors in config

## License

MIT
