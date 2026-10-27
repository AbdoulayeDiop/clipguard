"""The ClipGuard shield, drawn from the design system's geometry.

The shield lives on a 24-unit grid (see assets/Marks in the design system):
a body path plus two redaction bars. Active = solid jade, paused = outline,
hold = solid amber (dialog only).
"""

from __future__ import annotations

from .theme import COLORS

# Shield body on the 24 grid: straight top, then two cubic curves to the point.
_TOP = [(12.0, 1.75), (20.25, 4.75), (20.25, 11.0)]
_RIGHT_CURVE = ((20.25, 11.0), (20.25, 16.1), (16.8, 20.1), (12.0, 22.25))
_LEFT_CURVE = ((12.0, 22.25), (7.2, 20.1), (3.75, 16.1), (3.75, 11.0))
BARS = [(7.5, 8.9, 9.0), (7.5, 12.9, 5.5)]  # x, y, width; height 2.4, corner 0.6


def _cubic(p0, p1, p2, p3, n):
    pts = []
    for i in range(1, n + 1):
        t = i / n
        a, b, c, d = (1 - t) ** 3, 3 * (1 - t) ** 2 * t, 3 * (1 - t) * t ** 2, t ** 3
        pts.append((a * p0[0] + b * p1[0] + c * p2[0] + d * p3[0],
                    a * p0[1] + b * p1[1] + c * p2[1] + d * p3[1]))
    return pts


def shield_points(scale: float = 1.0, ox: float = 0.0, oy: float = 0.0, n: int = 14):
    pts = list(_TOP) + _cubic(*_RIGHT_CURVE, n) + _cubic(*_LEFT_CURVE, n) + [(3.75, 4.75)]
    return [(ox + x * scale, oy + y * scale) for x, y in pts]


def bar_rects(scale: float = 1.0, ox: float = 0.0, oy: float = 0.0):
    return [(ox + x * scale, oy + y * scale, ox + (x + w) * scale, oy + (y + 2.4) * scale)
            for x, y, w in BARS]


def inks(state: str, theme: str) -> tuple[str, str]:
    """(body colour, bar colour) for a state in a theme."""
    c = COLORS[theme]
    if state == "paused":
        return c["ink-muted"], c["ink-muted"]
    if state == "hold":
        return c["hold-mark"], c["surface-raised"]
    return c["guard"], c["on-guard"]


def make_icon(active: bool = True, size: int = 64, theme: str = "light"):
    from PIL import Image, ImageDraw

    big = 512
    s = big / 24
    img = Image.new("RGBA", (big, big), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    body, bar = inks("active" if active else "paused", theme)
    pts = shield_points(s)
    if active:
        d.polygon(pts, fill=body)
    else:
        d.line(pts + [pts[0], pts[1]], fill=body, width=round(1.9 * s), joint="curve")
    for r in bar_rects(s):
        d.rounded_rectangle(r, radius=0.6 * s, fill=bar)
    return img.resize((size, size), Image.LANCZOS)


def save_ico(path: str) -> None:
    make_icon(True, 256, "light").save(
        path, sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (256, 256)])
