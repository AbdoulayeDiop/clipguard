"""Draws ClipGuard's shield icon with Pillow (no image files to ship)."""

from __future__ import annotations

from PIL import Image, ImageDraw

ACTIVE = (31, 157, 85)    # green
PAUSED = (128, 134, 145)  # grey


def _shield(s: float) -> list[tuple[float, float]]:
    pts = [(0.50 * s, 0.06 * s), (0.86 * s, 0.18 * s), (0.86 * s, 0.48 * s)]
    # Right curve down to the bottom point, then mirror for the left side.
    for i in range(1, 9):
        t = i / 9
        pts.append(((0.86 - 0.36 * t ** 1.4) * s, (0.48 + 0.46 * t) * s))
    pts.append((0.50 * s, 0.95 * s))
    left = [(s - x, y) for x, y in reversed(pts[1:-1])]
    return pts + left


def make_icon(active: bool = True, size: int = 64) -> Image.Image:
    big = 256
    img = Image.new("RGBA", (big, big), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.polygon(_shield(big), fill=ACTIVE if active else PAUSED)
    w = int(big * 0.09)
    if active:  # check mark
        d.line([(0.32 * big, 0.50 * big), (0.45 * big, 0.64 * big), (0.70 * big, 0.36 * big)],
               fill="white", width=w, joint="curve")
    else:       # pause bars
        for x in (0.40, 0.60):
            d.rectangle([(x - 0.05) * big, 0.34 * big, (x + 0.05) * big, 0.66 * big], fill="white")
    return img.resize((size, size), Image.LANCZOS)


def save_ico(path: str) -> None:
    make_icon(True, 256).save(path, sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (256, 256)])
