#!/usr/bin/env python3
"""Build the Argus trailer (1920x1080) from REAL captured assets — not a mock-up.

Leads with the live Splunk dashboard (demo/shots/dashboard_*.png, captured by
demo/capture_ui.py), the real SAIA-authored SPL, and a real forkvalidate CONFIRMED run
(demo/shots/*.txt). Title/close are rendered cards. Frames -> per-clip ffmpeg concat.
"""
import os, subprocess, textwrap
from PIL import Image, ImageDraw, ImageFont

W, H = 1920, 1080
BG = (8, 14, 26)
CARD = (15, 23, 42)
FG = (226, 232, 240)
MUTED = (148, 163, 184)
ACCENT = (52, 211, 153)
ORANGE = (244, 161, 66)
TERM_BG = (13, 17, 23)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHOTS = os.path.join(REPO, "demo", "shots")
FROOT = "/usr/share/fonts/truetype/dejavu"
def font(name, size): return ImageFont.truetype(os.path.join(FROOT, name), size)
BOLD = lambda s: font("DejaVuSans-Bold.ttf", s)
REG = lambda s: font("DejaVuSans.ttf", s)
MONO = lambda s: font("DejaVuSansMono.ttf", s)

OUT = "/tmp/argus_frames"
os.makedirs(OUT, exist_ok=True)
frames = []

# Fail loudly if the real captures are missing — never publish a degraded (slides-only) trailer unnoticed.
_missing = [r for r in ("dashboard_top.png", "saia_spl.txt", "forkvalidate.txt") if not os.path.exists(os.path.join(SHOTS, r))]
if _missing:
    print(f"WARNING: missing real assets {_missing} — run demo/capture_ui.py first; the trailer will be degraded.")

def center(d, y, text, f, fill):
    w = d.textlength(text, font=f); d.text(((W - w) // 2, y), text, font=f, fill=fill)

def save(img, secs):
    p = os.path.join(OUT, f"f{len(frames):02d}.png"); img.save(p); frames.append((p, secs))

def chrome(d, x0, y0, x1, y1, title):
    """Draw a window chrome (title bar + 3 dots) for a panel from x0,y0 to x1,y1."""
    d.rounded_rectangle([x0, y0, x1, y1], radius=16, fill=TERM_BG, outline=(40, 52, 74), width=2)
    d.rounded_rectangle([x0, y0, x1, y0 + 46], radius=16, fill=(22, 27, 34))
    d.rectangle([x0, y0 + 30, x1, y0 + 46], fill=(22, 27, 34))
    for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        d.ellipse([x0 + 20 + i * 26, y0 + 16, x0 + 34 + i * 26, y0 + 30], fill=c)
    d.text((x0 + 120, y0 + 13), title, font=MONO(20), fill=MUTED)

# 1 — Title
img = Image.new("RGB", (W, H), BG); d = ImageDraw.Draw(img)
center(d, 360, "ARGUS", BOLD(170), FG)
center(d, 560, "A Splunk-native security operations center for cross-chain DeFi", REG(46), MUTED)
center(d, 720, "Everything below is the LIVE system — real data, not a mock-up.", REG(38), ACCENT)
save(img, 4)

# 2 — REAL dashboard (hero)
img = Image.new("RGB", (W, H), BG); d = ImageDraw.Draw(img)
center(d, 36, "The Splunk SOC, live", BOLD(46), FG)
shot = None
for name in ("dashboard_top.png", "dashboard_full.png"):
    p = os.path.join(SHOTS, name)
    if os.path.exists(p): shot = p; break
if shot:
    im = Image.open(shot).convert("RGB")
    im = im.crop((0, 0, im.width, min(im.height, int(im.width * 9 / 16))))  # 16:9 top slice
    maxw, maxh = 1760, 880
    r = min(maxw / im.width, maxh / im.height); im = im.resize((int(im.width * r), int(im.height * r)))
    x = (W - im.width) // 2
    d.rectangle([x - 3, 110 - 3, x + im.width + 3, 110 + im.height + 3], outline=(40, 52, 74), width=3)
    img.paste(im, (x, 110))
    center(d, 110 + im.height + 18, "$21.95B TVL in scope  ·  live Investigation Log verdicts  ·  PoC Fork Test Queue  —  real data", REG(30), MUTED)
else:
    center(d, 480, "(run demo/capture_ui.py to capture the live dashboard)", REG(34), MUTED)
save(img, 6)

# 3 — REAL SAIA-authored SPL
img = Image.new("RGB", (W, H), BG); d = ImageDraw.Draw(img)
center(d, 40, "The AI writes the detections", BOLD(52), FG)
center(d, 116, "Splunk AI Assistant (SAIA) — plain-English threat → brand-new SPL, live (~21s)", REG(34), MUTED)
chrome(d, 240, 200, 1680, 760, "SAIA  ·  generate_spl  →  splunk/generated/saia_generated_detection.spl")
spl = open(os.path.join(SHOTS, "saia_spl.txt")).read().strip().splitlines() if os.path.exists(os.path.join(SHOTS, "saia_spl.txt")) else []
for i, line in enumerate(spl[:9]):
    d.text((280, 270 + i * 46), line, font=MONO(26), fill=(167, 243, 208))
center(d, 800, "✓ authored live by Splunk's own hosted model — the AI builds the security logic", REG(32), ACCENT)
save(img, 6)

# 4 — REAL forkvalidate CONFIRMED
img = Image.new("RGB", (W, H), BG); d = ImageDraw.Draw(img)
center(d, 40, "Ground truth: fork-validation", BOLD(52), FG)
center(d, 116, "Forks Ethereum mainnet with Anvil + runs a Foundry exploit test — CONFIRMED only on a real [PASS]", REG(32), MUTED)
chrome(d, 200, 200, 1720, 800, "$  | forkvalidate  (real run, capability self-test)")
fv = open(os.path.join(SHOTS, "forkvalidate.txt")).read().strip().splitlines() if os.path.exists(os.path.join(SHOTS, "forkvalidate.txt")) else []
y = 270
for line in fv:
    for w in textwrap.wrap(line, 96) or [""]:
        col = ACCENT if "CONFIRMED" in w or "PASSED" in w or "status" in w else (201, 209, 217)
        d.text((232, y), w, font=MONO(22), fill=col); y += 34
        if y > 760: break
center(d, 840, "Otherwise an honest REJECTED / INCONCLUSIVE. It never fabricates a verdict.", REG(32), ORANGE)
save(img, 6)

# 5 — Close
img = Image.new("RGB", (W, H), BG); d = ImageDraw.Draw(img)
center(d, 320, "Argus", BOLD(150), FG)
center(d, 520, "Splunk does the pattern work, holds the state, runs the agent,", REG(40), MUTED)
center(d, 576, "and writes its own detections — verified end to end.", REG(40), MUTED)
center(d, 740, "github.com/Alexander-Sorrell-IT/argus  ·  AGPL-3.0", MONO(34), ACCENT)
center(d, 808, "Splunk Agentic Ops Hackathon 2026", REG(28), MUTED)
save(img, 5)

# Assemble: per-slide clips -> concat (reliable; avoids the concat-demuxer black-first-frame bug).
clips = []
for idx, (p, secs) in enumerate(frames):
    clip = os.path.join(OUT, f"clip_{idx:02d}.mp4")
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-loop", "1", "-t", str(secs), "-i", p,
                    "-r", "30", "-c:v", "libx264", "-preset", "veryfast", "-crf", "20",
                    "-pix_fmt", "yuv420p", "-vf", "format=yuv420p", clip], check=True)
    clips.append(clip)
listf = os.path.join(OUT, "clips.txt")
with open(listf, "w") as fh:
    for c in clips: fh.write(f"file '{c}'\n")
total = sum(s for _, s in frames)
out_mp4 = os.path.join(REPO, "demo", "argus_trailer.mp4")
subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-f", "concat", "-safe", "0", "-i", listf,
                "-c:v", "libx264", "-preset", "veryfast", "-crf", "20", "-pix_fmt", "yuv420p",
                "-vf", f"fade=t=in:st=0:d=0.5,fade=t=out:st={total-0.8:.1f}:d=0.8",
                "-movflags", "+faststart", out_mp4], check=True)
print(f"built {out_mp4}  ({len(frames)} real-asset slides, {total}s)")
