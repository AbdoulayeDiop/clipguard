Standalone executables, no Python needed.

**Windows:** download `clipguard-background-windows-x64.exe` and double-click it. A shield appears in the notification area of the taskbar (click the ^ arrow if it's hidden). Right-click it to pause, change settings or quit. `clipguard-windows-x64.exe` does the same but also opens a console window with logs.

### New in 0.3.0: a proper design
- **Redesigned paste dialog.** Secrets in the preview are drawn as solid redaction bars, each finding has a HIGH / MED / LOW tag, and the safe choice (Paste masked) is the one that stands out. Keyboard: Enter pastes masked, Esc cancels, Tab moves between buttons.
- **Light and dark.** The dialog follows Windows' app theme (including a dark title bar), and the tray icon follows the taskbar theme.
- **New shield.** Solid when ClipGuard is watching, outline when paused, so the state is clear even without colour.
- **Atkinson Hyperlegible typefaces,** bundled. They keep look-alike characters (0/O, 1/l/I) distinct, which matters when checking a key.
- **Sharper on high-DPI screens.**
- **Clearer notifications:** "Credit card number copied · ClipGuard will ask before you paste it."
