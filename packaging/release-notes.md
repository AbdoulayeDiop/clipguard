Standalone executables, no Python needed.

**Windows:** download `clipguard-background-windows-x64.exe` and double-click it. A shield appears in the notification area of the taskbar (click the ^ arrow if it's hidden). Click it to open Settings; right-click it to pause or quit. `clipguard-windows-x64.exe` does the same but also opens a console window with logs.

### New in 0.4.0: a real Settings window
- **Settings, no text file.** Click the shield (or Settings in its menu). Three tabs:
  - **Protection:** ask before pasting secrets, what to alert on (secrets only / plus financial details / everything), clear a copied secret after 30 s, 1 min or 5 min, start ClipGuard when you sign in, keep a detection log.
  - **Detectors:** turn individual detectors off, grouped by severity.
  - **Exceptions:** values never to flag, such as a public test key, entered and shown masked.
- **Changes apply on Save,** with no restart. Hand edits to `config.toml` are picked up automatically too.
- **Start at sign-in** is now a checkbox instead of a manual shortcut.
