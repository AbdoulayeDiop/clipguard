"""The paste dialog, drawn with tkinter from the ClipGuard design system.

Anatomy (see PasteDialog in the design system): hold shield, PASTE ON HOLD,
a title that counts the secrets, one line of guidance, finding rows, the
preview well with redaction bars, a caption, then Cancel / Paste original /
Paste masked.
"""

from __future__ import annotations

from typing import Callable

from .detectors import Finding, mask_parts
from .icon import bar_rects, inks, shield_points
from .theme import RADIUS, Theme

MASKED, ORIGINAL, CANCEL = "masked", "original", "cancel"
PREVIEW_CHARS = 600
MAX_ROWS = 5
WIDTH = 520  # px, design-system max width


def _round_rect(cv, x1, y1, x2, y2, r, **kw):
    """A rounded rectangle on a Canvas (smoothed polygon)."""
    r = max(0, min(r, (x2 - x1) / 2, (y2 - y1) / 2))
    pts = [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r, x2, y2 - r, x2, y2,
           x2 - r, y2, x1 + r, y2, x1, y2, x1, y2 - r, x1, y1 + r, x1, y1]
    return cv.create_polygon(pts, smooth=True, splinesteps=12, **kw)


class _Button:
    """Canvas button: primary / secondary / quiet, with optional keycap and focus ring."""

    def __init__(self, parent, t: Theme, text: str, variant: str, command, shortcut: str | None = None):
        import tkinter as tk

        self.t, self.variant, self.command = t, variant, command
        c = t.c
        self.fill = {"primary": c["guard"], "secondary": c["surface-raised"], "quiet": c["surface-raised"]}[variant]
        self.hover = {"primary": c["guard-strong"], "secondary": c["guard-tint"], "quiet": c["surface-raised"]}[variant]
        self.fg = {"primary": c["on-guard"], "secondary": c["ink"], "quiet": c["ink-muted"]}[variant]
        self.fg_hover = c["ink"] if variant == "quiet" else self.fg
        self.border = c["line-strong"] if variant == "secondary" else ""

        font, kfont = t.fonts["body-strong"], t.fonts["tag"]
        padx = t.space(2) if variant == "quiet" else t.space(4)
        ring = t.px(4)  # room for the 2px focus ring + 2px offset
        text_w = font.measure(text)
        key_w = kfont.measure(shortcut) + t.space(1) * 2 if shortcut else 0
        gap = t.space(2) if shortcut else 0
        w, h = text_w + gap + key_w + padx * 2, t.px(36)
        self.cv = tk.Canvas(parent, width=w + ring * 2, height=h + ring * 2, bg=c["surface-raised"],
                            highlightthickness=0, bd=0, takefocus=1, cursor="hand2")
        x1, y1, x2, y2 = ring, ring, ring + w, ring + h
        self.ring = _round_rect(self.cv, x1 - t.px(3), y1 - t.px(3), x2 + t.px(3), y2 + t.px(3),
                                t.px(RADIUS["md"] + 3), fill="", outline="", width=t.px(2))
        self.body = _round_rect(self.cv, x1, y1, x2, y2, t.px(RADIUS["md"]), fill=self.fill,
                                outline=self.border, width=1 if self.border else 0)
        self.label = self.cv.create_text(x1 + padx, (y1 + y2) / 2, text=text, anchor="w", font=font, fill=self.fg)
        self.key = self.keytext = None
        if shortcut:
            kx = x1 + padx + text_w + gap
            kh = kfont.metrics("linespace") + t.px(4)
            ky = (y1 + y2 - kh) / 2
            if variant == "primary":
                self.key = _round_rect(self.cv, kx, ky, kx + key_w, ky + kh, t.px(RADIUS["sm"]),
                                       fill="", outline=self.fg, width=1)
            else:
                self.key = _round_rect(self.cv, kx, ky, kx + key_w, ky + kh, t.px(RADIUS["sm"]),
                                       fill=c["neutral-tint"], outline="")
            self.keytext = self.cv.create_text(kx + key_w / 2, ky + kh / 2, text=shortcut, font=kfont,
                                               fill=self.fg if variant == "primary" else c["ink-muted"])
        self.cv.bind("<Enter>", lambda e: self._paint(True))
        self.cv.bind("<Leave>", lambda e: self._paint(False))
        self.cv.bind("<Button-1>", lambda e: self.command())
        self.cv.bind("<space>", lambda e: self.command())
        self.cv.bind("<FocusIn>", lambda e: self.cv.itemconfigure(self.ring, outline=t.c["focus"]))
        self.cv.bind("<FocusOut>", lambda e: self.cv.itemconfigure(self.ring, outline=""))

    def _paint(self, hover: bool) -> None:
        self.cv.itemconfigure(self.body, fill=self.hover if hover else self.fill)
        self.cv.itemconfigure(self.label, fill=self.fg_hover if hover else self.fg)


def _tag(parent, t: Theme, severity: str):
    import tkinter as tk

    c = t.c
    text = {"high": "HIGH", "medium": "MED", "low": "LOW"}.get(severity, severity.upper())
    fg, bg = {"high": (c["alert"], c["alert-tint"]), "medium": (c["hold"], c["hold-tint"]),
              "low": (c["ink-muted"], c["neutral-tint"])}.get(severity, (c["ink-muted"], c["neutral-tint"]))
    font = t.fonts["tag"]
    w = max(font.measure("HIGH"), font.measure(text)) + t.space(2) * 2
    h = font.metrics("linespace") + t.px(6)
    cv = tk.Canvas(parent, width=w, height=h, bg=c["surface-raised"], highlightthickness=0, bd=0)
    _round_rect(cv, 0, 0, w, h, t.px(RADIUS["sm"]), fill=bg, outline="")
    cv.create_text(w / 2, h / 2, text=text, font=font, fill=fg)
    return cv


def _masked_value(parent, t: Theme, value: str):
    """Kept characters followed by a redaction bar, in the mono face."""
    import tkinter as tk

    c = t.c
    kept, hidden = mask_parts(value)
    font = t.fonts["value-small"]
    ch = font.measure("0")
    h = font.metrics("linespace")
    kw = font.measure(kept)
    w = kw + ch * hidden
    cv = tk.Canvas(parent, width=w, height=h, bg=c["surface-raised"], highlightthickness=0, bd=0)
    if kept:
        cv.create_text(0, h / 2, text=kept, anchor="w", font=font, fill=c["ink"])
    bh = round(h * 0.62)
    cv.create_rectangle(kw, (h - bh) / 2, w, (h + bh) / 2, fill=c["redact"], outline="")
    return cv


def _shield(parent, t: Theme, state: str, size: int):
    import tkinter as tk

    body, bar = inks(state, t.name)
    cv = tk.Canvas(parent, width=size, height=size, bg=t.c["surface-raised"], highlightthickness=0, bd=0)
    s = size / 24
    cv.create_polygon([v for p in shield_points(s) for v in p], fill=body, outline="")
    for x1, y1, x2, y2 in bar_rects(s):
        _round_rect(cv, x1, y1, x2, y2, 0.6 * s, fill=bar, outline="")
    return cv


def _dark_title_bar(top) -> None:
    """Ask Windows 10/11 for a dark title bar to match the dark theme."""
    try:
        import ctypes
        hwnd = int(top.wm_frame(), 16)
        value = ctypes.c_int(1)
        for attr in (20, 19):  # DWMWA_USE_IMMERSIVE_DARK_MODE (new, old builds)
            if ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, attr, ctypes.byref(value), 4) == 0:
                break
    except Exception:
        pass


def ask_paste_choice(
    root,
    findings: list[Finding],
    segments: list[tuple[str, bool]],
    on_shown: Callable[[object], None] | None = None,
    auto_choice: str | None = None,
    theme: Theme | None = None,
) -> str:
    """Show the paste dialog modally and return MASKED, ORIGINAL or CANCEL.

    `segments` is the masked paste from redact_segments(): hidden runs are
    drawn as redaction bars. `on_shown(toplevel)` lets the caller force focus;
    `auto_choice` presses a button after a second (tests).
    """
    import platform
    import tkinter as tk

    t = theme or Theme(root)
    c = t.c
    result = {"choice": CANCEL}

    top = tk.Toplevel(root, bg=c["surface-raised"])
    top.withdraw()
    top.title("ClipGuard")
    top.resizable(False, False)
    top.attributes("-topmost", True)
    if platform.system() == "Windows" and t.name == "dark":
        _dark_title_bar(top)

    def choose(choice: str) -> None:
        result["choice"] = choice
        top.destroy()

    pad = t.space(6)
    inner = t.px(WIDTH) - pad * 2
    body = tk.Frame(top, bg=c["surface-raised"], padx=pad)
    body.pack(fill="both", expand=True, pady=(pad, 0))

    def label(parent, text, style, color="ink", **kw):
        return tk.Label(parent, text=text, font=t.fonts[style], fg=c[color], bg=c["surface-raised"],
                        anchor="w", justify="left", **kw)

    def hairline(parent):
        tk.Frame(parent, height=1, bg=c["line"]).pack(fill="x")

    # Header ------------------------------------------------------------------
    head = tk.Frame(body, bg=c["surface-raised"])
    head.pack(fill="x")
    shield_size = t.px(36)
    _shield(head, t, "hold", shield_size).pack(side="left", anchor="n", padx=(0, t.space(3)))
    text_col = tk.Frame(head, bg=c["surface-raised"])
    text_col.pack(side="left", fill="x", expand=True)
    label(text_col, "PASTE ON HOLD", "eyebrow", "hold").pack(anchor="w", pady=(0, t.px(2)))
    kinds: dict[str, Finding] = {}
    for f in findings:
        kinds.setdefault(f.label, f)
    n = len(kinds)
    label(text_col, f"This paste contains {n} secret{'s' if n != 1 else ''}", "title",
          wraplength=inner - shield_size - t.space(3)).pack(anchor="w")
    label(text_col, "Paste a masked copy, or the original if you trust where it's going.", "body",
          "ink-muted", wraplength=inner - shield_size - t.space(3)).pack(anchor="w")

    # Findings ----------------------------------------------------------------
    rows = tk.Frame(body, bg=c["surface-raised"])
    rows.pack(fill="x", pady=(t.space(4), 0))
    hairline(rows)
    for f in list(kinds.values())[:MAX_ROWS]:
        row = tk.Frame(rows, bg=c["surface-raised"], pady=t.space(2))
        row.pack(fill="x")
        _tag(row, t, f.severity).pack(side="left", padx=(0, t.space(3)))
        _masked_value(row, t, f.match).pack(side="right")
        label(row, f.label, "body").pack(side="left", fill="x", expand=True)
        hairline(rows)
    if n > MAX_ROWS:
        label(rows, f"+{n - MAX_ROWS} more", "caption", "ink-muted").pack(anchor="w", pady=(t.space(1), 0))

    # Preview -----------------------------------------------------------------
    label(body, "WHAT WILL BE PASTED", "eyebrow", "ink-muted").pack(anchor="w", pady=(t.space(4), t.space(2)))
    text_len, shown, truncated = 0, [], False
    for s, hidden in segments:
        if text_len + len(s) > PREVIEW_CHARS:
            s, truncated = s[:PREVIEW_CHARS - text_len], True
        shown.append((s, hidden))
        text_len += len(s)
        if truncated:
            break
    preview_text = "".join(s for s, _ in shown)
    mono = t.fonts["value"]
    chars_per_line = max(20, (inner - t.space(4) * 2) // max(1, mono.measure("0")))
    est_lines = sum(max(1, -(-len(line) // chars_per_line)) for line in preview_text.split("\n"))
    well = tk.Text(body, height=min(7, max(2, est_lines)), wrap="char", font=mono,
                   bg=c["surface-sunken"], fg=c["ink"], relief="flat", bd=0,
                   highlightthickness=1, highlightbackground=c["line"], highlightcolor=c["line"],
                   padx=t.space(4), pady=t.space(3), spacing1=t.px(2), spacing3=t.px(2),
                   cursor="arrow", takefocus=0, width=1)
    well.tag_configure("bar", background=c["redact"], foreground=c["redact"])
    for s, hidden in shown:
        well.insert("end", s, ("bar",) if hidden else ())
    if truncated:
        well.insert("end", "…")
    well.configure(state="disabled")
    well.pack(fill="x")
    label(body, "Your clipboard keeps the original.", "caption", "ink-muted").pack(anchor="w", pady=(t.space(2), 0))

    # Actions -----------------------------------------------------------------
    # Button canvases reserve `ring` px around the button for the focus ring,
    # so the row sits `ring` px further out to keep the visible edges aligned.
    ring = t.px(4)
    actions = tk.Frame(top, bg=c["surface-raised"], padx=pad - ring)
    actions.pack(fill="x", pady=(t.space(4) - ring, pad - ring))
    cancel = _Button(actions, t, "Cancel", "quiet", lambda: choose(CANCEL), "Esc")
    cancel.cv.pack(side="left")
    primary = _Button(actions, t, "Paste masked", "primary", lambda: choose(MASKED), "Enter")
    primary.cv.pack(side="right")
    original = _Button(actions, t, "Paste original", "secondary", lambda: choose(ORIGINAL))
    original.cv.pack(side="right", padx=(0, max(0, t.space(2) - 2 * ring)))
    buttons = {cancel.cv: CANCEL, original.cv: ORIGINAL, primary.cv: MASKED}

    def on_return(_e):
        choose(buttons.get(top.focus_get(), MASKED))

    top.protocol("WM_DELETE_WINDOW", lambda: choose(CANCEL))
    top.bind("<Return>", on_return)
    top.bind("<KP_Enter>", on_return)
    top.bind("<Escape>", lambda e: choose(CANCEL))

    # Width is fixed by the design; height follows content.
    body.configure(width=t.px(WIDTH))
    top.update_idletasks()
    w = t.px(WIDTH)
    h = top.winfo_reqheight()
    x = (top.winfo_screenwidth() - w) // 2
    y = max(0, (top.winfo_screenheight() - h) // 3)
    top.geometry(f"{w}x{h}+{x}+{y}")
    top.deiconify()
    top.lift()
    top.update()
    if on_shown:
        try:
            on_shown(top)
        except Exception:
            pass
    top.focus_force()
    primary.cv.focus_set()

    if auto_choice in (MASKED, ORIGINAL, CANCEL):
        top.after(1000, lambda: choose(auto_choice))

    top.grab_set()
    root.wait_window(top)
    return result["choice"]
