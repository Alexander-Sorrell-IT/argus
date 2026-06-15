#!/usr/bin/env python3
"""Render architecture_wide.png — a 1920x1080 landscape closed-loop diagram of Argus.
Ingest -> Detect -> Triage -> Prove -> CONFIRMED, with the return loop and a SAIA callout."""
import os
from PIL import Image, ImageDraw, ImageFont

W, H = 1920, 1080
BG = (8, 14, 26)
FROOT = "/usr/share/fonts/truetype/dejavu"
def f(n, s): return ImageFont.truetype(os.path.join(FROOT, n), s)
BOLD, REG, MONO = (lambda s: f("DejaVuSans-Bold.ttf", s)), (lambda s: f("DejaVuSans.ttf", s)), (lambda s: f("DejaVuSansMono.ttf", s))
FG, MUTED, ACCENT, ORANGE, BLUE = (226,232,240),(148,163,184),(52,211,153),(244,161,66),(125,211,252)

img = Image.new("RGB", (W, H), BG); d = ImageDraw.Draw(img)
def center(y, t, fo, c, x=W//2):
    w = d.textlength(t, font=fo); d.text((x - w//2, y), t, font=fo, fill=c)

center(56, "ARGUS — the detect → prove loop, all on Splunk", BOLD(52), FG)
center(126, "Splunk does the pattern work, holds the state, runs the agent, and writes its own detections", REG(28), MUTED)

# 5 stage boxes, left to right
stages = [
    ("INGEST", ["on-chain tx / events", "source · audit · scope", "→ typed sourcetypes"], BLUE),
    ("DETECT", ["pure SPL: z-score,", "streamstats, predict,", "cluster + mechanism rule"], ACCENT),
    ("TRIAGE", ["in-app agent (modular", "input) · KV-deduped ·", "deterministic verdict"], ACCENT),
    ("PROVE", ["| forkvalidate:", "Anvil mainnet fork +", "Foundry exploit test"], ORANGE),
    ("CONFIRMED", ["real [PASS] only ·", "else REJECTED /", "INCONCLUSIVE"], ACCENT),
]
n = len(stages); bw, bh, gap = 300, 230, 48
total = n*bw + (n-1)*gap; x0 = (W - total)//2; y = 300
centers = []
for i, (title, lines, col) in enumerate(stages):
    x = x0 + i*(bw+gap); cx = x + bw//2; centers.append((cx, y, x, x+bw))
    d.rounded_rectangle([x, y, x+bw, y+bh], radius=20, fill=(15,23,42), outline=col, width=3)
    center(y+22, title, BOLD(40), col, x=cx)
    for j, ln in enumerate(lines):
        center(y+92+j*34, ln, REG(24), MUTED, x=cx)
    if i < n-1:  # forward arrow
        ax0 = x+bw+8; ax1 = ax0+gap-16; ay = y+bh//2
        d.line([ax0, ay, ax1, ay], fill=FG, width=4)
        d.polygon([(ax1, ay), (ax1-14, ay-9), (ax1-14, ay+9)], fill=FG)

# SAIA callout into DETECT
detect_cx = centers[1][0]
d.rounded_rectangle([detect_cx-180, 600, detect_cx+180, 690], radius=14, fill=(15,23,42), outline=BLUE, width=2)
center(616, "SAIA (Splunk AI Assistant)", BOLD(24), BLUE, x=detect_cx)
center(652, "writes new SPL detections", REG(22), MUTED, x=detect_cx)
d.line([detect_cx, 600, detect_cx, centers[1][1]+bh], fill=BLUE, width=3)
d.polygon([(detect_cx, centers[1][1]+bh), (detect_cx-9, centers[1][1]+bh+14), (detect_cx+9, centers[1][1]+bh+14)], fill=BLUE)

# return loop: CONFIRMED -> back to TRIAGE/state (the closed loop)
cf_cx = centers[4][0]; tr_cx = centers[2][0]; ly = y+bh+150
d.line([cf_cx, y+bh, cf_cx, ly], fill=ACCENT, width=3)
d.line([cf_cx, ly, tr_cx, ly], fill=ACCENT, width=3)
d.line([tr_cx, ly, tr_cx, y+bh], fill=ACCENT, width=3)
d.polygon([(tr_cx, y+bh), (tr_cx-9, y+bh+14), (tr_cx+9, y+bh+14)], fill=ACCENT)
center(ly+12, "verdict written back as layerzero:ai_report / fork_result  →  dashboard + KV state  (the loop closes)", REG(24), ACCENT, x=(cf_cx+tr_cx)//2)

# footer: where state lives
center(980, "State: Splunk KV store (per-contract baselines, agent dedup)   ·   Output: 10 typed sourcetypes, persistent in the index", MONO(22), MUTED)
center(1024, "github.com/Alexander-Sorrell-IT/argus", MONO(22), ACCENT)

out = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "architecture_wide.png")
img.save(out)
print("wrote", out, img.size)
