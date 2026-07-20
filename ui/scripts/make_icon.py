"""Génère favicon.ico (icône desktop Windows) à partir du logo 02 RED SHIELD.

Dessine le bouclier « coche brillante » (fond navy dégradé, contour orange,
reflet, coche orange) en supersampling puis exporte un .ico multi-tailles.
Lancer : engine/.venv/Scripts/python.exe ui/scripts/make_icon.py
"""
from __future__ import annotations
import os
from PIL import Image, ImageDraw

S = 1024                      # toile de travail (supersampling)
K = S / 128.0                 # facteur d'échelle depuis le viewBox 128x142
def p(x, y):                  # viewBox -> pixels (léger décalage vertical)
    return (x * K, (y + 1) * (S / 142.0))

def cubic(p0, p1, p2, p3, n=60):
    out = []
    for i in range(n + 1):
        t = i / n; u = 1 - t
        x = u*u*u*p0[0] + 3*u*u*t*p1[0] + 3*u*t*t*p2[0] + t*t*t*p3[0]
        y = u*u*u*p0[1] + 3*u*u*t*p1[1] + 3*u*t*t*p2[1] + t*t*t*p3[1]
        out.append((x, y))
    return out

# Contour du bouclier (mêmes points que le SVG)
pts = [p(64, 6), p(112, 24), p(112, 62)]
pts += cubic(p(112, 62), p(112, 96), p(92, 120), p(64, 134))
pts += cubic(p(64, 134), p(36, 120), p(16, 96), p(16, 62))
pts += [p(16, 24), p(64, 6)]

img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
d = ImageDraw.Draw(img)

# --- fond dégradé navy (clair en haut-gauche -> sombre en bas) ---
grad = Image.new("RGBA", (S, S), (0, 0, 0, 0))
gd = ImageDraw.Draw(grad)
top = (35, 58, 92); bot = (10, 21, 38)
for y in range(S):
    t = y / S
    r = int(top[0] + (bot[0]-top[0]) * t)
    g = int(top[1] + (bot[1]-top[1]) * t)
    b = int(top[2] + (bot[2]-top[2]) * t)
    gd.line([(0, y), (S, y)], fill=(r, g, b, 255))
mask = Image.new("L", (S, S), 0)
ImageDraw.Draw(mask).polygon(pts, fill=255)
img.paste(grad, (0, 0), mask)

# --- reflet brillant (haut-gauche) ---
gloss = [p(64, 8), p(24, 23), p(37, 80), p(46, 49), p(46, 19)]
gl = Image.new("RGBA", (S, S), (0, 0, 0, 0))
ImageDraw.Draw(gl).polygon(gloss, fill=(255, 255, 255, 70))
img = Image.alpha_composite(img, gl)
d = ImageDraw.Draw(img)

# --- contour orange épais ---
d.line(pts, fill=(255, 122, 47, 255), width=int(9 * K), joint="curve")

# --- coche orange (avec jointures arrondies) ---
chk = [p(44, 64), p(58, 79), p(88, 46)]
w = int(11 * K)
d.line(chk, fill=(255, 154, 77, 255), width=w, joint="curve")
for (cx, cy) in chk:
    rr = w / 2
    d.ellipse([cx-rr, cy-rr, cx+rr, cy+rr], fill=(255, 154, 77, 255))

# --- export .ico multi-tailles ---
here = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "public")
sizes = [256, 128, 64, 48, 32, 24, 16]
icons = [img.resize((s, s), Image.LANCZOS) for s in sizes]
ico_path = os.path.join(here, "favicon.ico")
icons[0].save(ico_path, format="ICO", sizes=[(s, s) for s in sizes])
# PNG 512 en bonus (raccourci desktop haute résolution)
img.resize((512, 512), Image.LANCZOS).save(os.path.join(here, "red-shield-512.png"))
print("OK ->", ico_path)
