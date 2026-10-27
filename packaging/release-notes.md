Standalone executables, no Python needed.

**Windows:** download `clipguard-background-windows-x64.exe` and double-click it. A green shield appears in the notification area of the taskbar (click the ^ arrow if it's hidden). Right-click it to pause, change settings or quit. `clipguard-windows-x64.exe` does the same but also opens a console window with logs.

### New in 0.2.0
- **Tray icon:** green shield while active, grey while paused. Menu: Pause, Ask before pasting sensitive data, Edit settings, Reload settings, Quit.
- **Paste guard (Windows):** pressing Ctrl+V with sensitive data on the clipboard opens a dialog to paste a masked version (e.g. `**** **** **** 1111`), the original, or nothing.
- Fewer false alarms: `pass: tomorrow` is no longer flagged, and French social security numbers are checked against their key.
- Notifications reveal fewer characters of short secrets.
