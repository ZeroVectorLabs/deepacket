"""Render assets/og.png, the 1200x630 link-preview card for Deepacket.

Usage: python3 tools/social_card.py assets/og.png   (needs Pillow, fontTools and brotli)
"""
from PIL import Image, ImageDraw, ImageFont, ImageFilter
import sys

import pathlib
R = str(pathlib.Path(__file__).resolve().parent.parent) + '/'
W, H = 1200, 630
BG = (6, 17, 31)
CYAN = (34, 211, 238)
WHITE = (238, 244, 250)
MUTED = (140, 160, 185)

import io
from fontTools.ttLib import TTFont
_cache = {}
def _ttf(name):
    if name not in _cache:
        t = TTFont(R + 'fonts/' + name); t.flavor = None
        buf = io.BytesIO(); t.save(buf); _cache[name] = buf.getvalue()
    return io.BytesIO(_cache[name])

def font(path, size, wght=None, wdth=None):
    f = ImageFont.truetype(_ttf(path), size)
    if wght is not None:
        try:
            vals = []
            for a in f.get_variation_axes():
                n = a['name'] if isinstance(a['name'], str) else a['name'].decode()
                if n.lower().startswith('weight'):
                    vals.append(wght)
                elif n.lower().startswith('width'):
                    vals.append(wdth or 100)
                else:
                    vals.append(a['default'])
            f.set_variation_by_axes(vals)
        except Exception as e:
            print('variation failed', e, file=sys.stderr)
    return f

card = Image.new('RGB', (W, H), BG)

# screenshot on the right, cropped to the top of the overview, with a cyan edge glow
shot = Image.open(R + 'docs/screenshots/overview.png').convert('RGB')
shot = shot.crop((0, 0, 1440, 900)).resize((900, 562), Image.LANCZOS)
sx, sy = 560, 120
glow = Image.new('RGBA', (W, H), (0, 0, 0, 0))
gd = ImageDraw.Draw(glow)
gd.rounded_rectangle((sx - 6, sy - 6, sx + 900 + 6, sy + 562 + 6), 18, fill=CYAN + (90,))
glow = glow.filter(ImageFilter.GaussianBlur(22))
card.paste(glow, (0, 0), glow)
mask = Image.new('L', shot.size, 0)
ImageDraw.Draw(mask).rounded_rectangle((0, 0, 900, 562), 14, fill=255)
card.paste(shot, (sx, sy), mask)
ImageDraw.Draw(card).rounded_rectangle((sx, sy, sx + 900, sy + 562), 14, outline=(40, 70, 100), width=2)

# left fade so the text stays readable over the screenshot edge
fade = Image.new('RGBA', (W, H), (0, 0, 0, 0))
fd = ImageDraw.Draw(fade)
for x in range(540, 700):
    a = int(255 * max(0, 1 - (x - 540) / 160))
    fd.line([(x, 0), (x, H)], fill=BG + (a,))
fd.rectangle((0, 0, 540, H), fill=BG + (255,))
card.paste(fade, (0, 0), fade)

d = ImageDraw.Draw(card)
logo = Image.open(R + 'assets/logo-128.png').convert('RGBA').resize((72, 72), Image.LANCZOS)
card.paste(logo, (64, 64), logo)
d.text((150, 74), 'Deepacket', font=font('archivo.woff2', 46, 700, 100), fill=WHITE)

h = font('archivo.woff2', 64, 800, 90)
d.text((64, 196), 'Open a capture.', font=h, fill=WHITE)
d.text((64, 268), 'Find the attack', font=h, fill=CYAN)
d.text((64, 340), 'in it.', font=h, fill=CYAN)

b = font('archivo.woff2', 26, 450, 100)
y = 440
for line in ['PCAP analyzer with MITRE ATT&CK', 'detections, attack flow and', 'file & credential extraction.']:
    d.text((64, y), line, font=b, fill=MUTED)
    y += 34

m = font('plex500.woff2', 20)
d.text((64, 566), 'Free · Open source · Runs in your browser', font=m, fill=CYAN)

out = sys.argv[1] if len(sys.argv) > 1 else 'og.png'
card.save(out, optimize=True)
print('saved', out)
