"""Generates the shield mark used by both the extension's toolbar icons and the web
app's favicon (frontend/public/favicon.svg is hand-authored from the same geometry
below, so keep SHIELD_POINTS/CHECK_POINTS in sync if you change this file).
Run with the backend venv (Pillow's a dependency there via xhtml2pdf):
    ..\..\backend\.venv\Scripts\python generate_icons.py
"""

from pathlib import Path

from PIL import Image, ImageDraw

CYAN_LIGHT = (103, 232, 249)  # #67e8f9
CYAN_DARK = (8, 145, 178)  # #0891b2
OUTLINE_COLOR = (14, 116, 144, 255)  # #0e7490
CHECK_COLOR = (255, 255, 255, 255)

# Shield silhouette in a normalized 0-100 coordinate space: flat top, narrowing
# to a point at the bottom — simple enough to stay legible at 16px.
SHIELD_POINTS = [
    (50, 4),
    (90, 18),
    (90, 46),
    (50, 97),
    (10, 46),
    (10, 18),
]

# A simple checkmark, positioned within the shield's lower-center. Only drawn at
# 32px+ — at 16px it washes out and a flat gradient shield reads more cleanly.
CHECK_POINTS = [
    (32, 48),
    (44, 60),
    (68, 32),
]


def _shield_mask(size: int) -> Image.Image:
    scale = size / 100
    mask = Image.new("L", (size, size), 0)
    draw = ImageDraw.Draw(mask)
    draw.polygon([(x * scale, y * scale) for x, y in SHIELD_POINTS], fill=255)
    return mask


def _vertical_gradient(size: int) -> Image.Image:
    gradient = Image.new("RGB", (1, size))
    for y in range(size):
        t = y / max(size - 1, 1)
        pixel = tuple(round(CYAN_LIGHT[i] + (CYAN_DARK[i] - CYAN_LIGHT[i]) * t) for i in range(3))
        gradient.putpixel((0, y), pixel)
    return gradient.resize((size, size))


def draw_icon(size: int) -> Image.Image:
    scale = size / 100
    mask = _shield_mask(size)
    fill = _vertical_gradient(size).convert("RGBA")
    fill.putalpha(mask)

    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    img.alpha_composite(fill)

    draw = ImageDraw.Draw(img)
    outline = [(x * scale, y * scale) for x, y in SHIELD_POINTS]
    draw.line(outline + [outline[0]], fill=OUTLINE_COLOR, width=max(1, round(size * 0.02)))

    if size >= 32:
        check = [(x * scale, y * scale) for x, y in CHECK_POINTS]
        draw.line(check, fill=CHECK_COLOR, width=max(2, round(size * 0.06)), joint="curve")

    return img


if __name__ == "__main__":
    out_dir = Path(__file__).parent
    for size in (16, 48, 128):
        draw_icon(size).save(out_dir / f"icon{size}.png")
        print(f"wrote icon{size}.png")
