# ClipGuard

A small background app that warns you when you copy something sensitive (a password, API key, card number, IBAN, private key) so you think twice before pasting it into a chat, an AI tool or the wrong window.

Works on macOS, Windows and Linux. Everything runs locally: nothing is sent anywhere, and the sensitive value is never written to disk or shown in full in notifications.

## What it detects

| Severity | Examples |
|---|---|
| High | AWS, GitHub, GitLab, OpenAI, Anthropic, Google, Stripe, Slack, Twilio, SendGrid, npm and Hugging Face keys; private keys; database URLs with passwords; `password=…` lines; credit card numbers (Luhn-checked); US SSNs; French NIR numbers |
| Medium | IBANs (mod-97 checked), JWTs, Slack webhooks, high-entropy strings that look like passwords |
| Low | Email addresses, phone numbers |

By default, alerts fire at **medium** and above. Run `clipguard detectors` for the full list.

## Install

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

- Alerts happen when you **copy**, not when you paste. Detecting *where* you paste needs OS-level accessibility hooks; that's on the roadmap.
- Detection is pattern-based. It will miss some secrets and occasionally flag harmless text; use `ignore_values` and `disabled_detectors` to tune it.
- On macOS the first notification may ask for permission for "Script Editor" (used to show notifications).

## Development

```bash
pip install -e ".[dev]"
pytest
```

Test secrets are assembled at runtime so no real-looking token appears in the source.

## Roadmap

- Menu bar / system tray icon with pause and resume
- Paste-time warnings for specific apps (browsers, chat apps)
- Per-app allowlist (e.g. don't alert when copying from your password manager)
- Custom regex detectors in config

## License

MIT
