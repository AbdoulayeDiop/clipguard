"""The Settings window: Protection, Detectors and Exceptions tabs.

Built with tkinter from the ClipGuard design system (theme.py). Saving writes
config.toml (atomically) and hands the new Config to `on_saved`; a running
ClipGuard also picks up the file change by itself.
"""

from __future__ import annotations

import platform
from dataclasses import replace
from typing import Callable

from . import autostart
from .config import Config, config_path, load_config, save_config, write_default_config
from .detectors import HIGH, LOW, MEDIUM, PATTERNS, mask
from .dialog import _Button, _round_rect, _tag
from .icon import bar_rects, inks, shield_points
from .theme import RADIUS, Theme

IS_WINDOWS = platform.system() == "Windows"

SEVERITY_CHOICES = [
    (HIGH, "Secrets only", "Keys, passwords, card numbers and ID numbers."),
    (MEDIUM, "Secrets and financial details", "Adds IBANs, tokens and random-looking strings."),
    (LOW, "Everything", "Adds email addresses and phone numbers."),
]
CLEAR_CHOICES = [(0, "Never"), (30, "30 s"), (60, "1 min"), (300, "5 min")]
TABS = ["Protection", "Detectors", "Exceptions"]
WIDTH, BODY_HEIGHT = 560, 500


def detector_catalog() -> list[tuple[str, str, str]]:
    """(id, label, severity) for every detector, highest severity first."""
    items = [(p.id, p.label, p.severity) for p in PATTERNS]
    items.append(("high_entropy", "Password or secret (random-looking)", MEDIUM))
    order = {HIGH: 0, MEDIUM: 1, LOW: 2}
    return sorted(items, key=lambda x: order[x[2]])


def clear_choices(current: float) -> list[tuple[float, str]]:
    choices = list(CLEAR_CHOICES)
    if current and current not in [c for c, _ in choices]:
        choices.append((current, f"{current:g} s"))
    return choices


class SettingsState:
    """Editable copy of the settings; no GUI, so it's unit-testable."""

    def __init__(self, cfg: Config, autostart_on: bool = False) -> None:
        self.base = cfg
        self.min_severity = cfg.min_severity
        self.auto_clear_seconds = cfg.auto_clear_seconds
        self.paste_guard = cfg.paste_guard
        self.log_detections = cfg.log_detections
        self.disabled = set(cfg.disabled_detectors)
        self.ignore_values = list(cfg.ignore_values)
        self.autostart = autostart_on

    def add_ignore(self, value: str) -> bool:
        value = value.strip()
        if not value or value in self.ignore_values:
            return False
        self.ignore_values.append(value)
        return True

    def to_config(self) -> Config:
        known = {d for d, _, _ in detector_catalog()}
        return replace(
            self.base,
            min_severity=self.min_severity,
            auto_clear_seconds=self.auto_clear_seconds,
            paste_guard=self.paste_guard,
            log_detections=self.log_detections,
            # keep ids we don't know (e.g. from a newer version) untouched
            disabled_detectors=sorted(self.disabled | (set(self.base.disabled_detectors) - known)),
            ignore_values=list(self.ignore_values),
        ).validate()


# --------------------------------------------------------------------------- widgets

class _Check:
    """Square checkbox (radius-sm) with a label and an optional caption."""

    def __init__(self, parent, t: Theme, label: str, caption: str | None, value: bool,
                 on_change: Callable[[bool], None], bg_key: str = "surface-raised", wrap: int | None = None):
        import tkinter as tk

        c = t.c
        self.t, self.value, self.on_change = t, value, on_change
        self.frame = tk.Frame(parent, bg=c[bg_key])
        size = t.px(18)
        self.box = tk.Canvas(self.frame, width=size + t.px(4), height=size + t.px(4), bg=c[bg_key],
                             highlightthickness=0, bd=0, takefocus=1, cursor="hand2")
        self.box.grid(row=0, column=0, rowspan=2, sticky="n", padx=(0, t.space(3)), pady=(t.px(1), 0))
        o = t.px(2)
        self.ring = _round_rect(self.box, 0, 0, size + 2 * o, size + 2 * o, t.px(RADIUS["sm"] + 2),
                                fill="", outline="", width=t.px(2))
        self.rect = _round_rect(self.box, o, o, o + size, o + size, t.px(RADIUS["sm"]),
                                fill="", outline=c["line-strong"], width=t.px(1.5))
        s = size / 18
        self.tick = self.box.create_line(o + 4.5 * s, o + 9.5 * s, o + 7.8 * s, o + 12.8 * s, o + 13.8 * s, o + 5.6 * s,
                                         fill=c["on-guard"], width=max(2, t.px(2)), capstyle="round", joinstyle="round")
        lab = tk.Label(self.frame, text=label, font=t.fonts["body-strong"], fg=c["ink"], bg=c[bg_key],
                       anchor="w", justify="left", cursor="hand2", wraplength=wrap or 0)
        lab.grid(row=0, column=1, sticky="w")
        if caption:
            tk.Label(self.frame, text=caption, font=t.fonts["caption"], fg=c["ink-muted"], bg=c[bg_key],
                     anchor="w", justify="left", wraplength=t.px(WIDTH - 140)).grid(row=1, column=1, sticky="w")
        for w in (self.box, lab):
            w.bind("<Button-1>", lambda e: self.toggle())
        self.box.bind("<space>", lambda e: self.toggle())
        self.box.bind("<FocusIn>", lambda e: self.box.itemconfigure(self.ring, outline=c["focus"]))
        self.box.bind("<FocusOut>", lambda e: self.box.itemconfigure(self.ring, outline=""))
        self.paint()

    def paint(self) -> None:
        c = self.t.c
        self.box.itemconfigure(self.rect, fill=c["guard"] if self.value else c["surface-raised"],
                               outline=c["guard"] if self.value else c["line-strong"])
        self.box.itemconfigure(self.tick, state="normal" if self.value else "hidden")

    def toggle(self) -> None:
        self.value = not self.value
        self.paint()
        self.on_change(self.value)


class _Radio:
    """One option of a radio group: circle, label, caption."""

    def __init__(self, parent, t: Theme, label: str, caption: str, selected: bool, on_select):
        import tkinter as tk

        c = t.c
        self.t, self.selected, self.on_select = t, selected, on_select
        self.frame = tk.Frame(parent, bg=c["surface-raised"])
        size = t.px(18)
        o = t.px(2)
        self.cv = tk.Canvas(self.frame, width=size + 2 * o, height=size + 2 * o, bg=c["surface-raised"],
                            highlightthickness=0, bd=0, takefocus=1, cursor="hand2")
        self.cv.grid(row=0, column=0, rowspan=2, sticky="n", padx=(0, t.space(3)), pady=(t.px(1), 0))
        self.ring = self.cv.create_oval(0, 0, size + 2 * o, size + 2 * o, outline="", width=t.px(2))
        self.outer = self.cv.create_oval(o, o, o + size, o + size, outline=c["line-strong"], width=t.px(1.5))
        d = size * 0.28
        self.dot = self.cv.create_oval(o + d, o + d, o + size - d, o + size - d, fill=c["guard"], outline="")
        lab = tk.Label(self.frame, text=label, font=t.fonts["body-strong"], fg=c["ink"], bg=c["surface-raised"],
                       anchor="w", cursor="hand2")
        lab.grid(row=0, column=1, sticky="w")
        tk.Label(self.frame, text=caption, font=t.fonts["caption"], fg=c["ink-muted"], bg=c["surface-raised"],
                 anchor="w").grid(row=1, column=1, sticky="w")
        for w in (self.cv, lab):
            w.bind("<Button-1>", lambda e: self.on_select())
        self.cv.bind("<space>", lambda e: self.on_select())
        self.cv.bind("<FocusIn>", lambda e: self.cv.itemconfigure(self.ring, outline=c["focus"]))
        self.cv.bind("<FocusOut>", lambda e: self.cv.itemconfigure(self.ring, outline=""))
        self.paint()

    def paint(self) -> None:
        c = self.t.c
        self.cv.itemconfigure(self.outer, outline=c["guard"] if self.selected else c["line-strong"])
        self.cv.itemconfigure(self.dot, state="normal" if self.selected else "hidden")


class _Segmented:
    """A row of joined options; the selected one is filled with guard."""

    def __init__(self, parent, t: Theme, choices, value, on_change):
        import tkinter as tk

        c = t.c
        self.t, self.choices, self.value, self.on_change = t, choices, value, on_change
        font = t.fonts["body-strong"]
        self.seg_w = max(font.measure(lbl) for _, lbl in choices) + t.space(4) * 2
        self.h = t.px(32)
        o = t.px(3)
        w = self.seg_w * len(choices)
        self.cv = tk.Canvas(parent, width=w + 2 * o, height=self.h + 2 * o, bg=c["surface-raised"],
                            highlightthickness=0, bd=0, takefocus=1, cursor="hand2")
        self.o = o
        self.cv.bind("<Button-1>", self._click)
        self.cv.bind("<Left>", lambda e: self._step(-1))
        self.cv.bind("<Right>", lambda e: self._step(1))
        self.cv.bind("<FocusIn>", lambda e: self.paint(focus=True))
        self.cv.bind("<FocusOut>", lambda e: self.paint(focus=False))
        self.paint()

    def _index(self) -> int:
        vals = [v for v, _ in self.choices]
        return vals.index(self.value) if self.value in vals else 0

    def _set(self, i: int) -> None:
        self.value = self.choices[i][0]
        self.paint(focus=True)
        self.on_change(self.value)

    def _click(self, e) -> None:
        self.cv.focus_set()
        self._set(max(0, min(len(self.choices) - 1, int((e.x - self.o) // self.seg_w))))

    def _step(self, d: int) -> None:
        self._set(max(0, min(len(self.choices) - 1, self._index() + d)))

    def paint(self, focus: bool = False) -> None:
        t, c, o, cv = self.t, self.t.c, self.o, self.cv
        cv.delete("all")
        w = self.seg_w * len(self.choices)
        if focus:
            _round_rect(cv, 0, 0, w + 2 * o, self.h + 2 * o, t.px(RADIUS["md"] + 3), fill="",
                        outline=c["focus"], width=t.px(2))
        _round_rect(cv, o, o, o + w, o + self.h, t.px(RADIUS["md"]), fill=c["surface-raised"],
                    outline=c["line-strong"], width=1)
        sel = self._index()
        x = o + sel * self.seg_w
        _round_rect(cv, x + 2, o + 2, x + self.seg_w - 2, o + self.h - 2, t.px(RADIUS["md"] - 2),
                    fill=c["guard"], outline="")
        for i, (_, lbl) in enumerate(self.choices):
            if 0 < i and i not in (sel, sel + 1):
                cv.create_line(o + i * self.seg_w, o + 6, o + i * self.seg_w, o + self.h - 6, fill=c["line"])
            cv.create_text(o + i * self.seg_w + self.seg_w / 2, o + self.h / 2, text=lbl,
                           font=t.fonts["body-strong"], fill=c["on-guard"] if i == sel else c["ink"])


def _scrollable(parent, t: Theme, height: int):
    """A vertically scrolling area; returns (outer frame, inner frame)."""
    import tkinter as tk

    c = t.c
    outer = tk.Frame(parent, bg=c["surface-raised"])
    cv = tk.Canvas(outer, height=height, bg=c["surface-raised"], highlightthickness=0, bd=0)
    inner = tk.Frame(cv, bg=c["surface-raised"])
    win = cv.create_window(0, 0, anchor="nw", window=inner)
    cv.pack(side="left", fill="both", expand=True)

    def on_inner(_e):
        cv.configure(scrollregion=(0, 0, inner.winfo_reqwidth(), inner.winfo_reqheight()))

    inner.bind("<Configure>", on_inner)
    cv.bind("<Configure>", lambda e: cv.itemconfigure(win, width=e.width))

    def wheel(e):
        if inner.winfo_reqheight() > cv.winfo_height():
            cv.yview_scroll(-1 if (getattr(e, "delta", 0) > 0 or getattr(e, "num", 0) == 4) else 1, "units")

    def bind(_e):
        cv.bind_all("<MouseWheel>", wheel)
        cv.bind_all("<Button-4>", wheel)
        cv.bind_all("<Button-5>", wheel)

    def unbind(_e):
        for seq in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            cv.unbind_all(seq)

    outer.bind("<Enter>", bind)
    outer.bind("<Leave>", unbind)
    return outer, inner


# --------------------------------------------------------------------------- window

def open_settings(root, on_saved: Callable[[Config], None] | None = None, theme: Theme | None = None,
                  config_file=None):
    """Open the Settings window (non-modal). Returns the Toplevel."""
    import tkinter as tk

    t = theme or Theme(root)
    c = t.c
    path = config_file or config_path()
    try:
        cfg = load_config(path)
        load_error = None
    except Exception as e:  # a broken file shouldn't lock people out of the window
        cfg, load_error = Config(), str(e)
    state = SettingsState(cfg, autostart.is_enabled())

    top = tk.Toplevel(root, bg=c["surface-raised"])
    top.withdraw()
    top.title("ClipGuard settings")
    top.resizable(False, False)
    if IS_WINDOWS and t.name == "dark":
        from .dialog import _dark_title_bar
        _dark_title_bar(top)

    pad = t.space(6)
    inner_w = t.px(WIDTH) - 2 * pad

    def label(parent, text, style, color="ink", **kw):
        return tk.Label(parent, text=text, font=t.fonts[style], fg=c[color], bg=c["surface-raised"],
                        anchor="w", justify="left", **kw)

    # Header -------------------------------------------------------------------
    head = tk.Frame(top, bg=c["surface-raised"], padx=pad)
    head.pack(fill="x", pady=(pad, 0))
    size = t.px(28)
    mark = tk.Canvas(head, width=size, height=size, bg=c["surface-raised"], highlightthickness=0, bd=0)
    body_ink, bar_ink = inks("active", t.name)
    s = size / 24
    mark.create_polygon([v for p in shield_points(s) for v in p], fill=body_ink, outline="")
    for x1, y1, x2, y2 in bar_rects(s):
        _round_rect(mark, x1, y1, x2, y2, 0.6 * s, fill=bar_ink, outline="")
    mark.pack(side="left", padx=(0, t.space(3)))
    label(head, "Settings", "title").pack(side="left")

    # Tabs ---------------------------------------------------------------------
    tabs = tk.Frame(top, bg=c["surface-raised"], padx=pad)
    tabs.pack(fill="x", pady=(t.space(4), 0))
    tab_canvases = []
    pages = {}
    current = {"tab": TABS[0]}

    def show(name):
        current["tab"] = name
        for n, (cv, txt, line) in zip(TABS, tab_canvases):
            on = n == name
            cv.itemconfigure(txt, fill=c["ink"] if on else c["ink-muted"])
            cv.itemconfigure(line, state="normal" if on else "hidden")
        for n, page in pages.items():
            page.pack_forget()
        pages[name].pack(fill="both", expand=True)

    for name in TABS:
        f = t.fonts["body-strong"]
        w, h = f.measure(name) + t.space(2) * 2, t.px(34)
        cv = tk.Canvas(tabs, width=w, height=h, bg=c["surface-raised"], highlightthickness=0, bd=0,
                       takefocus=1, cursor="hand2")
        txt = cv.create_text(w / 2, h / 2 - t.px(2), text=name, font=f, fill=c["ink-muted"])
        line = cv.create_rectangle(t.space(2), h - t.px(2), w - t.space(2), h, fill=c["guard"], outline="")
        cv.bind("<Button-1>", lambda e, n=name: show(n))
        cv.bind("<space>", lambda e, n=name: show(n))
        cv.bind("<FocusIn>", lambda e, cv=cv: cv.configure(highlightthickness=0))
        cv.pack(side="left", padx=(0, t.space(2)))
        tab_canvases.append((cv, txt, line))
    tk.Frame(top, height=1, bg=c["line"]).pack(fill="x", padx=pad)

    body = tk.Frame(top, bg=c["surface-raised"], padx=pad)
    body.pack(fill="both", expand=True)

    def page(name):
        outer, inner = _scrollable(body, t, t.px(BODY_HEIGHT))
        pages[name] = outer
        inner.configure(pady=t.space(4))
        return inner

    def gap(parent, n=4):
        tk.Frame(parent, height=t.space(n), bg=c["surface-raised"]).pack(fill="x")

    # Protection ---------------------------------------------------------------
    p = page("Protection")
    if IS_WINDOWS:
        _Check(p, t, "Ask before pasting secrets",
               "When you press Ctrl+V with a secret on the clipboard, choose to paste it masked.",
               state.paste_guard, lambda v: setattr(state, "paste_guard", v)).frame.pack(fill="x")
        gap(p, 6)
    label(p, "ALERT ME ABOUT", "eyebrow", "ink-muted").pack(anchor="w", pady=(0, t.space(2)))
    radios = []

    def select(level):
        state.min_severity = level
        for r, (lv, _, _) in zip(radios, SEVERITY_CHOICES):
            r.selected = lv == level
            r.paint()

    for lv, name, caption in SEVERITY_CHOICES:
        r = _Radio(p, t, name, caption, state.min_severity == lv, lambda lv=lv: select(lv))
        r.frame.pack(fill="x", pady=(0, t.space(3)))
        radios.append(r)
    gap(p, 3)
    label(p, "CLEAR A COPIED SECRET", "eyebrow", "ink-muted").pack(anchor="w", pady=(0, t.space(2)))
    seg = _Segmented(p, t, clear_choices(state.auto_clear_seconds), state.auto_clear_seconds,
                     lambda v: setattr(state, "auto_clear_seconds", v))
    seg.cv.pack(anchor="w", padx=(-0, 0))
    label(p, "Removes high-severity items from the clipboard if they're still there.", "caption",
          "ink-muted").pack(anchor="w", pady=(t.space(1), 0))
    gap(p, 6)
    if autostart.available():
        _Check(p, t, "Start ClipGuard when I sign in", None, state.autostart,
               lambda v: setattr(state, "autostart", v)).frame.pack(fill="x", pady=(0, t.space(4)))
    _Check(p, t, "Keep a detection log",
           "Records what kind of data was found and when, never the data itself.",
           state.log_detections, lambda v: setattr(state, "log_detections", v)).frame.pack(fill="x")

    # Detectors ----------------------------------------------------------------
    d = page("Detectors")
    label(d, "Turn off a detector if it flags things you don't consider sensitive.", "body", "ink-muted",
          wraplength=inner_w).pack(anchor="w", pady=(0, t.space(4)))
    groups = {}
    for det_id, det_label, sev in detector_catalog():
        groups.setdefault(sev, []).append((det_id, det_label))
    for sev in (HIGH, MEDIUM, LOW):
        items = groups.get(sev, [])
        if not items:
            continue
        hdr = tk.Frame(d, bg=c["surface-raised"])
        hdr.pack(fill="x", pady=(t.space(2), t.space(2)))
        _tag(hdr, t, sev).pack(side="left")
        label(hdr, f"{len(items)} detector{'s' if len(items) != 1 else ''}", "caption", "ink-muted").pack(
            side="left", padx=(t.space(2), 0))
        grid = tk.Frame(d, bg=c["surface-raised"])
        grid.pack(fill="x")
        grid.columnconfigure(0, weight=1, uniform="det")
        grid.columnconfigure(1, weight=1, uniform="det")
        for i, (det_id, det_label) in enumerate(items):
            def change(v, det_id=det_id):
                (state.disabled.discard if v else state.disabled.add)(det_id)
            chk = _Check(grid, t, det_label, None, det_id not in state.disabled, change,
                         wrap=inner_w // 2 - t.px(40))
            chk.frame.grid(row=i // 2, column=i % 2, sticky="w", pady=(0, t.space(2)))
        gap(d, 2)

    # Exceptions ---------------------------------------------------------------
    x = page("Exceptions")
    label(x, "NEVER FLAG THESE VALUES", "eyebrow", "ink-muted").pack(anchor="w", pady=(0, t.space(1)))
    label(x, "For public test keys or demo card numbers you copy often. They're kept in your settings "
             "file on this computer.", "caption", "ink-muted", wraplength=inner_w).pack(anchor="w")
    add_row = tk.Frame(x, bg=c["surface-raised"])
    add_row.pack(fill="x", pady=(t.space(3), t.space(3)))
    entry_box = tk.Frame(add_row, bg=c["line-strong"], padx=1, pady=1)
    entry_box.pack(side="left", fill="x", expand=True, padx=(0, t.space(2)))
    entry = tk.Entry(entry_box, show="•", font=t.fonts["value"], bg=c["surface-raised"], fg=c["ink"],
                     insertbackground=c["ink"], relief="flat", bd=t.px(6),
                     highlightthickness=0)
    entry.pack(fill="x")
    entry.bind("<FocusIn>", lambda e: entry_box.configure(bg=c["focus"]))
    entry.bind("<FocusOut>", lambda e: entry_box.configure(bg=c["line-strong"]))
    listing = tk.Frame(x, bg=c["surface-raised"])
    listing.pack(fill="x")

    def render_list():
        for w in listing.winfo_children():
            w.destroy()
        if not state.ignore_values:
            label(listing, "No exceptions yet.", "body", "ink-muted").pack(anchor="w", pady=(t.space(2), 0))
            return
        tk.Frame(listing, height=1, bg=c["line"]).pack(fill="x")
        for v in state.ignore_values:
            row = tk.Frame(listing, bg=c["surface-raised"])
            row.pack(fill="x")
            label(row, mask(v), "value", "ink").pack(side="left", pady=t.space(1))

            def remove(v=v):
                state.ignore_values.remove(v)
                render_list()
            _Button(row, t, "Remove", "quiet", remove).cv.pack(side="right")
            tk.Frame(listing, height=1, bg=c["line"]).pack(fill="x")

    def add_value():
        if state.add_ignore(entry.get()):
            entry.delete(0, "end")
            render_list()

    entry.bind("<Return>", lambda e: (add_value(), "break")[1])
    _Button(add_row, t, "Add", "secondary", add_value).cv.pack(side="right")
    render_list()

    # Footer -------------------------------------------------------------------
    sep = tk.Frame(top, height=1, bg=c["line"])
    sep.pack(fill="x")
    ring = t.px(4)
    foot = tk.Frame(top, bg=c["surface-raised"], padx=pad - ring)
    foot.pack(fill="x", pady=(t.space(4) - ring, pad - ring))
    status = tk.Label(top, font=t.fonts["caption"], fg=c["alert"], bg=c["surface-raised"], anchor="w",
                      justify="left", wraplength=inner_w)

    def show_status(msg: str) -> None:
        status.configure(text=msg)
        status.pack(fill="x", padx=pad, pady=(0, t.space(3)), before=sep)

    def save():
        try:
            new = state.to_config()
            save_config(new, path)
            if autostart.available() and state.autostart != autostart.is_enabled():
                autostart.set_enabled(state.autostart)
        except Exception as e:
            show_status(f"Couldn't save: {e}")
            return
        if on_saved:
            on_saved(new)
        top.destroy()

    def open_file():
        from .tray import open_path
        open_path(write_default_config(path))

    _Button(foot, t, "Open settings file", "quiet", open_file).cv.pack(side="left")
    primary = _Button(foot, t, "Save", "primary", save, "Enter")
    primary.cv.pack(side="right")
    _Button(foot, t, "Cancel", "secondary", top.destroy).cv.pack(side="right",
                                                               padx=(0, max(0, t.space(2) - 2 * ring)))
    if load_error:
        show_status(f"Your settings file has an error, so defaults are shown. Saving will replace it. ({load_error})")

    def on_return(e):
        if e.widget is entry:
            return
        save()

    top.bind("<Return>", on_return)
    top.bind("<Escape>", lambda e: top.destroy())

    show(TABS[0])
    top.update_idletasks()
    w = t.px(WIDTH)
    h = top.winfo_reqheight()
    top.geometry(f"{w}x{h}+{(top.winfo_screenwidth() - w) // 2}+{max(0, (top.winfo_screenheight() - h) // 3)}")
    top.deiconify()
    top.lift()
    top.focus_force()
    primary.cv.focus_set()
    top._clipguard_show_tab = show  # used by tests and screenshots
    return top


def run_standalone() -> int:
    """`clipguard settings`: the window on its own (macOS/Linux tray, or from a shell)."""
    import tkinter as tk

    from .theme import enable_dpi_awareness, load_fonts

    enable_dpi_awareness()
    load_fonts()
    root = tk.Tk()
    root.withdraw()
    win = open_settings(root)
    win.bind("<Destroy>", lambda e: root.quit() if e.widget is win else None)
    root.mainloop()
    return 0
