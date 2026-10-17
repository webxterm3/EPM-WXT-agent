#!/usr/bin/env python3
"""Draw the wxt-agent application icon.

Generated rather than committed as a binary blob so the shape, the colours and
the rounding are reviewable and can be changed by editing numbers rather than
by opening a graphics program.

The mark is a shield — the product governs what may run on a machine — with a
terminal caret inside it, because the thing being governed is a computer and
the caret is the one glyph everybody reads as "machine" without a label. macOS
renders app icons at sizes down to 16px, so the shape stays a silhouette with
one interior element; anything busier turns to mush at the small end.
"""

import math
import os
import sys

from PIL import Image, ImageDraw

# Rendered at 1024 and downsampled, so every edge is antialiased by the
# resampler rather than by hand at each size.
SIZE = 1024

# A deep slate that reads as "system software" rather than "consumer app", and
# a single accent for the mark itself.
BG_TOP = (28, 36, 54)
BG_BOTTOM = (16, 22, 34)
SHIELD = (56, 211, 185)
SHIELD_SHADE = (38, 170, 149)
CARET = (12, 18, 28)


def rounded_rect_mask(size: int, radius: int) -> Image.Image:
    mask = Image.new("L", (size, size), 0)
    d = ImageDraw.Draw(mask)
    d.rounded_rectangle([0, 0, size - 1, size - 1], radius=radius, fill=255)
    return mask


def vertical_gradient(size: int, top, bottom) -> Image.Image:
    grad = Image.new("RGB", (1, size))
    for y in range(size):
        t = y / (size - 1)
        grad.putpixel((0, y), tuple(round(top[i] + (bottom[i] - top[i]) * t) for i in range(3)))
    return grad.resize((size, size))


def shield_points(cx: float, cy: float, w: float, h: float):
    """A shield: rounded shoulders, flanks that taper to a soft point.

    Drawn from numbers rather than traced, so the proportions can be adjusted
    without a graphics program. The taper starts just under halfway down: start
    it lower and the silhouette reads as a cup, which is what the first attempt
    did.
    """
    half = w / 2
    top = cy - h / 2
    bottom = cy + h / 2
    shoulder = top + h * 0.42
    corner = w * 0.18

    pts = []

    # Top edge with rounded corners, so the shape has no hard square top.
    steps = 16
    for i in range(steps + 1):
        a = math.pi + (i / steps) * (math.pi / 2)
        pts.append((cx - half + corner + corner * math.cos(a),
                    top + corner + corner * math.sin(a)))
    for i in range(steps + 1):
        a = -math.pi / 2 + (i / steps) * (math.pi / 2)
        pts.append((cx + half - corner + corner * math.cos(a),
                    top + corner + corner * math.sin(a)))

    # Flanks. A quadratic Bezier from the shoulder to the tip, with its
    # control point out at the full width and low down: that is what makes the
    # sides fall almost straight and then turn in hard at the end, which is the
    # difference between a shield and a rounded rectangle. Easing functions
    # were tried first and all of them produced a cup.
    pts.append((cx + half, shoulder))

    def bezier(p0, p1, p2, steps=56):
        out = []
        for i in range(1, steps + 1):
            t = i / steps
            u = 1 - t
            out.append((u * u * p0[0] + 2 * u * t * p1[0] + t * t * p2[0],
                        u * u * p0[1] + 2 * u * t * p1[1] + t * t * p2[1]))
        return out

    tip = (cx, bottom)
    pts += bezier((cx + half, shoulder), (cx + half, bottom - h * 0.06), tip)
    pts += bezier(tip, (cx - half, bottom - h * 0.06), (cx - half, shoulder))

    pts.append((cx - half, shoulder))

    return pts


def draw_icon() -> Image.Image:
    base = vertical_gradient(SIZE, BG_TOP, BG_BOTTOM).convert("RGBA")
    base.putalpha(rounded_rect_mask(SIZE, radius=int(SIZE * 0.2235)))

    layer = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)

    cx, cy = SIZE / 2, SIZE * 0.485
    w, h = SIZE * 0.52, SIZE * 0.60

    # A darker shield behind, offset down, so the mark has depth at large sizes
    # and simply looks slightly thicker at small ones.
    d.polygon(shield_points(cx, cy + SIZE * 0.014, w, h), fill=SHIELD_SHADE)
    d.polygon(shield_points(cx, cy, w, h), fill=SHIELD)

    # The caret: ">" with an underscore. Drawn with thick strokes and sized
    # generously, because at 16px this is the only interior detail and a thin
    # one disappears entirely.
    stroke = int(SIZE * 0.045)
    arm = SIZE * 0.082
    ax = cx - SIZE * 0.112
    ay = cy - SIZE * 0.105
    d.line([(ax, ay), (ax + arm, ay + arm)], fill=CARET, width=stroke, joint="curve")
    d.line([(ax + arm, ay + arm), (ax, ay + arm * 2)], fill=CARET, width=stroke, joint="curve")
    d.line([(cx + SIZE * 0.012, ay + arm * 2), (cx + SIZE * 0.115, ay + arm * 2)],
           fill=CARET, width=stroke)

    return Image.alpha_composite(base, layer)


def svg_mark() -> str:
    """The same shield and caret as a compact monochrome SVG.

    Emitted from the SAME numbers as the bitmap, which is the whole point of
    this file: the product had three unrelated logos — a heart, an infinity
    symbol and a stock shield glyph — because each surface picked its own. One
    source means the app icon, the favicon and the in-app mark cannot drift
    apart again.

    Real curve commands rather than the polygon the bitmap is filled from: the
    sampled version is a path with several hundred line segments, which is a
    silly thing to ship in a React component and resizes badly besides.

    Monochrome and in currentColor, because in-app the mark sits inside a
    tinted box that already supplies the colour; a second palette inside it
    fights the theme.
    """
    # The same proportions as draw_icon, in viewBox units.
    cx, cy = 50.0, 48.5
    w, h = 52.0, 60.0
    half, top, bottom = w / 2, cy - h / 2, cy + h / 2
    shoulder = top + h * 0.42
    r = w * 0.18
    waist = bottom - h * 0.06

    shield = (
        f"M{cx - half + r:.2f} {top:.2f}"
        f"H{cx + half - r:.2f}"
        f"A{r:.2f} {r:.2f} 0 0 1 {cx + half:.2f} {top + r:.2f}"
        f"V{shoulder:.2f}"
        f"Q{cx + half:.2f} {waist:.2f} {cx:.2f} {bottom:.2f}"
        f"Q{cx - half:.2f} {waist:.2f} {cx - half:.2f} {shoulder:.2f}"
        f"V{top + r:.2f}"
        f"A{r:.2f} {r:.2f} 0 0 1 {cx - half + r:.2f} {top:.2f}"
        "Z"
    )

    # The caret, positioned as in the bitmap.
    arm = 8.2
    ax, ay = cx - 11.2, cy - 10.5
    stroke = 4.5

    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" fill="none">'
        f'<path d="{shield}" fill="currentColor"/>'
        f'<g stroke="var(--mark-knockout,#0c121c)" stroke-width="{stroke}" '
        'stroke-linecap="round" stroke-linejoin="round">'
        f'<path d="M{ax:.1f} {ay:.1f}l{arm:.1f} {arm:.1f}l-{arm:.1f} {arm:.1f}"/>'
        f'<path d="M{cx + 1.2:.1f} {ay + arm * 2:.1f}h10.3"/>'
        "</g></svg>\n"
    )


def badged_icon(connected: bool) -> Image.Image:
    """The icon with a status badge, for the Windows notification area.

    Two ready-made images rather than one icon with an overlay drawn at
    runtime: the tray asks for an HICON and swapping between two is a single
    call, whereas compositing one with GDI at every state change is a pile of
    device contexts to leak.

    The badge is deliberately large and high-contrast. This is rendered at
    16x16 in a crowded tray, next to a dozen other icons, and the one thing it
    has to answer across a room is "green or red".
    """
    icon = draw_icon()
    d = ImageDraw.Draw(icon)

    # Bottom-right quadrant, in a filled disc so the mark reads against the
    # shield behind it at any size.
    cx, cy, r = SIZE * 0.715, SIZE * 0.715, SIZE * 0.225
    fill = (46, 184, 114) if connected else (219, 68, 68)
    d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=fill)
    d.ellipse([cx - r, cy - r, cx + r, cy + r], outline=BG_BOTTOM, width=int(SIZE * 0.022))

    w = int(SIZE * 0.045)
    mark = (255, 255, 255)
    if connected:
        d.line([(cx - r * 0.45, cy), (cx - r * 0.08, cy + r * 0.38), (cx + r * 0.5, cy - r * 0.42)],
               fill=mark, width=w, joint="curve")
    else:
        a = r * 0.42
        d.line([(cx - a, cy - a), (cx + a, cy + a)], fill=mark, width=w)
        d.line([(cx + a, cy - a), (cx - a, cy + a)], fill=mark, width=w)

    return icon


def write_ico(img: Image.Image, path: str):
    """A multi-size .ico. Windows picks a size out of it, and a single large
    entry scaled down to 16px in the tray turns to mush."""
    img.save(path, format="ICO",
             sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (256, 256)])


def main(out_dir: str):
    icon = draw_icon()
    iconset = os.path.join(out_dir, "wxt-agent.iconset")
    os.makedirs(iconset, exist_ok=True)

    # The sizes iconutil expects. Both scales of each, because a Retina Mac
    # picks the @2x and a 16px icon downsampled from 1024 is not the same thing
    # as one drawn for 32.
    for size in (16, 32, 128, 256, 512):
        icon.resize((size, size), Image.LANCZOS).save(
            os.path.join(iconset, f"icon_{size}x{size}.png"))
        icon.resize((size * 2, size * 2), Image.LANCZOS).save(
            os.path.join(iconset, f"icon_{size}x{size}@2x.png"))

    icon.save(os.path.join(out_dir, "wxt-agent-1024.png"))

    # Web assets, from the same drawing.
    icon.resize((512, 512), Image.LANCZOS).save(os.path.join(out_dir, "icon.png"))
    # A multi-size .ico: browsers and Windows both pick a size out of it, and a
    # single 256px entry gets scaled badly in a 16px tab strip.
    icon.resize((256, 256), Image.LANCZOS).save(
        os.path.join(out_dir, "favicon.ico"), format="ICO",
        sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])

    # The two tray states.
    write_ico(badged_icon(True), os.path.join(out_dir, "wxt-agent-connected.ico"))
    write_ico(badged_icon(False), os.path.join(out_dir, "wxt-agent-disconnected.ico"))

    with open(os.path.join(out_dir, "wxt-agent-mark.svg"), "w") as f:
        f.write(svg_mark())

    # The copies that live in the repositories, refreshed from the same
    # drawing. Written here rather than copied by hand, because three logos is
    # exactly what happens when each surface keeps its own file.
    here = os.path.dirname(os.path.abspath(__file__))
    repo = os.path.dirname(os.path.dirname(here))
    frontend = os.path.join(os.path.dirname(repo), "vsay-terminal-next", "public")

    for src, dst in [
        ("favicon.ico", os.path.join(repo, "internal", "brand", "wxt-agent.ico")),
        ("wxt-agent-connected.ico", os.path.join(repo, "internal", "brand", "wxt-agent-connected.ico")),
        ("wxt-agent-disconnected.ico", os.path.join(repo, "internal", "brand", "wxt-agent-disconnected.ico")),
        ("favicon.ico", os.path.join(frontend, "favicon.ico")),
        ("icon.png", os.path.join(frontend, "icon.png")),
        ("wxt-agent-mark.svg", os.path.join(frontend, "mark.svg")),
    ]:
        target_dir = os.path.dirname(dst)
        if not os.path.isdir(target_dir):
            continue
        with open(os.path.join(out_dir, src), "rb") as f_in, open(dst, "wb") as f_out:
            f_out.write(f_in.read())

    print(iconset)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else ".")
