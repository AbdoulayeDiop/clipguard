"""The "paste masked?" dialog, built with tkinter (bundled with Python)."""

from __future__ import annotations

from typing import Callable

from .detectors import Finding

MASKED, ORIGINAL, CANCEL = "masked", "original", "cancel"
PREVIEW_CHARS = 600


def ask_paste_choice(
    root,
    findings: list[Finding],
    masked_text: str,
    on_shown: Callable[[object], None] | None = None,
    auto_choice: str | None = None,
) -> str:
    """Show a modal dialog and return MASKED, ORIGINAL or CANCEL.

    `on_shown(toplevel)` lets the caller force focus onto the window.
    `auto_choice` clicks a button automatically after a second (used by tests).
    """
    import tkinter as tk
    from tkinter import ttk

    result = {"choice": CANCEL}
    top = tk.Toplevel(root)
    top.title("ClipGuard")
    top.resizable(False, False)
    top.attributes("-topmost", True)

    def choose(choice: str) -> None:
        result["choice"] = choice
        top.destroy()

    top.protocol("WM_DELETE_WINDOW", lambda: choose(CANCEL))
    top.bind("<Return>", lambda e: choose(MASKED))
    top.bind("<Escape>", lambda e: choose(CANCEL))

    body = ttk.Frame(top, padding=(20, 16, 20, 16))
    body.pack(fill="both", expand=True)

    head = ttk.Frame(body)
    head.pack(fill="x")
    tk.Label(head, text="⚠", font=("Segoe UI Symbol", 26), fg="#C77700").pack(side="left", padx=(0, 12))
    titles = ttk.Frame(head)
    titles.pack(side="left", fill="x")
    ttk.Label(titles, text="You're about to paste sensitive data",
              font=("Segoe UI", 12, "bold")).pack(anchor="w")
    ttk.Label(titles, text="ClipGuard paused this paste. What should it paste?",
              foreground="#555555").pack(anchor="w")

    found = ttk.Frame(body, padding=(0, 12, 0, 4))
    found.pack(fill="x")
    labels: dict[str, Finding] = {}
    for f in findings:
        labels.setdefault(f.label, f)
    for label, f in list(labels.items())[:5]:
        row = ttk.Frame(found)
        row.pack(fill="x", pady=1)
        ttk.Label(row, text="• " + label).pack(side="left")
        ttk.Label(row, text=f.masked, foreground="#777777", font=("Consolas", 9)).pack(side="right")
    if len(labels) > 5:
        ttk.Label(found, text=f"… and {len(labels) - 5} more").pack(anchor="w")

    ttk.Label(body, text="Masked version:", padding=(0, 8, 0, 2)).pack(anchor="w")
    preview = masked_text if len(masked_text) <= PREVIEW_CHARS else masked_text[:PREVIEW_CHARS] + "…"
    lines = min(6, max(2, preview.count("\n") + 1, len(preview) // 60 + 1))
    box = tk.Text(body, height=lines, width=60, wrap="word", font=("Consolas", 10),
                  relief="solid", borderwidth=1, background="#F7F7F7", padx=6, pady=4)
    box.insert("1.0", preview)
    box.configure(state="disabled")
    box.pack(fill="x")

    buttons = ttk.Frame(body, padding=(0, 14, 0, 0))
    buttons.pack(fill="x")
    primary = ttk.Button(buttons, text="Paste masked", command=lambda: choose(MASKED), default="active")
    primary.pack(side="right")
    ttk.Button(buttons, text="Paste original", command=lambda: choose(ORIGINAL)).pack(side="right", padx=(0, 8))
    ttk.Button(buttons, text="Cancel", command=lambda: choose(CANCEL)).pack(side="right", padx=(0, 8))

    # Center on screen.
    top.update_idletasks()
    w, h = top.winfo_reqwidth(), top.winfo_reqheight()
    x = (top.winfo_screenwidth() - w) // 2
    y = (top.winfo_screenheight() - h) // 3
    top.geometry(f"+{x}+{y}")
    top.deiconify()
    top.lift()
    top.update()
    if on_shown:
        try:
            on_shown(top)
        except Exception:
            pass
    top.focus_force()
    primary.focus_set()

    if auto_choice in (MASKED, ORIGINAL, CANCEL):
        top.after(1000, lambda: choose(auto_choice))

    top.grab_set()
    root.wait_window(top)
    return result["choice"]
