"""Native desktop notifications without heavy dependencies.

Message text is passed to helper processes via argv/environment, never
interpolated into a script, so clipboard content can't inject commands.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys

_SYSTEM = platform.system()

_MAC_SCRIPT = """
on run argv
    display notification (item 2 of argv) with title (item 1 of argv) sound name "Basso"
end run
"""

_WIN_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
$xml.LoadXml('<toast><visual><binding template="ToastGeneric"><text/><text/></binding></visual><audio src="ms-winsoundevent:Notification.Default"/></toast>')
$nodes = $xml.GetElementsByTagName('text')
$nodes.Item(0).AppendChild($xml.CreateTextNode($env:CG_TITLE)) | Out-Null
$nodes.Item(1).AppendChild($xml.CreateTextNode($env:CG_BODY)) | Out-Null
$appId = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($appId).Show(
    [Windows.UI.Notifications.ToastNotification]::new($xml))
"""


def notify(title: str, body: str, urgent: bool = False) -> bool:
    """Show a desktop notification. Returns True if a native one was shown."""
    try:
        if _SYSTEM == "Darwin" and shutil.which("osascript"):
            subprocess.run(["osascript", "-e", _MAC_SCRIPT, title, body],
                           check=True, capture_output=True, timeout=10)
            return True
        if _SYSTEM == "Windows":
            env = dict(os.environ, CG_TITLE=title, CG_BODY=body)
            subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", _WIN_SCRIPT],
                check=True, capture_output=True, timeout=15, env=env,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            return True
        if shutil.which("notify-send"):
            subprocess.run(
                ["notify-send", "-u", "critical" if urgent else "normal",
                 "-a", "ClipGuard", "-i", "dialog-warning", "--", title, body],
                check=True, capture_output=True, timeout=10)
            return True
    except (subprocess.SubprocessError, OSError):
        pass
    # Fallback: terminal bell + stderr.
    print(f"\a[ClipGuard] {title}: {body}", file=sys.stderr, flush=True)
    return False
