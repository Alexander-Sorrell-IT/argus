#!/usr/bin/env python3
"""Build the Argus trailer (1920x1080) from real, verified data. Frames -> ffmpeg."""
import os, subprocess
from PIL import Image, ImageDraw, ImageFont

W, H = 1920, 1080
BG = (8, 14, 26)          # deep navy
CARD = (15, 23, 42)
FG = (226, 232, 240)
MUTED = (148, 163, 184)
ACCENT = (52, 211, 153)   # green
ORANGE = (244, 161, 66)
MONO_BG = (2, 6, 16)

FROOT = "/usr/share/fonts/truetype/dejavu"
def f(name, size): return ImageFont.truetype(os.path.join(FROOT, name), size)
BOLD = lambda s: f("DejaVuSans-Bold.ttf", s)
REG  = lambda s: f("DejaVuSans.ttf", s)
MONO = lambda s: f("DejaVuSansMono.ttf", s)

OUT = "/tmp/argus_frames"
os.makedirs(OUT, exist_ok=True)

def center(d, y, text, font, fill):
    w = d.textlength(text, font=font); d.text(((W-w)//2, y), text, font=font, fill=fill)

def new(bg=BG):
    img = Image.new("RGB", (W, H), bg); return img, ImageDraw.Draw(img)

def chip(d, cx, cy, big, small, color):
    bw, bh = 360, 220
    x0, y0 = cx-bw//2, cy-bh//2
    d.rounded_rectangle([x0, y0, x0+bw, y0+bh], radius=22, fill=CARD, outline=color, width=3)
    w = d.textlength(big, font=BOLD(74)); d.text((cx-w//2, cy-70), big, font=BOLD(74), fill=color)
    w = d.textlength(small, font=REG(30)); d.text((cx-w//2, cy+30), small, font=REG(30), fill=MUTED)

frames = []
def save(img, secs):
    p = os.path.join(OUT, f"f{len(frames):02d}.png"); img.save(p); frames.append((p, secs))

# 1 — Title
img, d = new()
center(d, 360, "ARGUS", BOLD(180), FG)
center(d, 560, "A Splunk-native security operations center", REG(52), MUTED)
center(d, 626, "for cross-chain DeFi protocols", REG(52), MUTED)
d.rounded_rectangle([760, 740, 1160, 812], radius=14, outline=ACCENT, width=3)
center(d, 756, "engine:  omni_guard", MONO(36), ACCENT)
save(img, 4)

# 2 — Problem
img, d = new()
center(d, 300, "Smart contracts run for years.", BOLD(72), FG)
center(d, 410, "There is no  tail -f  for a live protocol.", BOLD(72), FG)
center(d, 600, "You hear about the exploit on Telegram —", REG(46), MUTED)
center(d, 666, "an hour after the funds are gone.", REG(46), MUTED)
center(d, 820, "Argus turns Splunk into a SOC for smart contracts.", REG(44), ACCENT)
save(img, 5)

# 3 — Architecture (real diagram)
img, d = new()
center(d, 70, "Everything runs on Splunk's own primitives", BOLD(56), FG)
try:
    arch = Image.open("architecture.png").convert("RGB")
    maxw, maxh = 1500, 780
    r = min(maxw/arch.width, maxh/arch.height)
    arch = arch.resize((int(arch.width*r), int(arch.height*r)))
    img.paste(arch, ((W-arch.width)//2, 180))
except Exception as e:
    center(d, 400, "SPL detections · KV store · in-app agent · fork-validation", REG(40), MUTED)
save(img, 5)

# 4 — Detection (SPL)
img, d = new()
center(d, 90, "Detection is pure SPL", BOLD(70), FG)
center(d, 200, "per-contract z-scores · streamstats · predict · MLTK", REG(38), MUTED)
box = [360, 300, 1560, 560]
d.rounded_rectangle(box, radius=16, fill=MONO_BG, outline=(40,52,74), width=2)
spl = ["index=omni_guard_security sourcetype=layerzero:transaction",
       "| eventstats avg(value_eth) stdev(value_eth) by contract_name",
       "| eval zscore=(value_eth-mean_v)/std_v | where zscore > 3",
       "| collect index=omni_guard_security sourcetype=layerzero:alert"]
for i, line in enumerate(spl):
    d.text((392, 330+i*52), line, font=MONO(28), fill=(125,211,252))
chip(d, 960, 760, "10", "real alerts fired", ORANGE)
save(img, 5)

# 5 — In-app AI agent
img, d = new()
center(d, 110, "An AI agent runs INSIDE Splunk", BOLD(70), FG)
center(d, 220, "a modular input on the Splunk Python SDK — triages every finding", REG(38), MUTED)
chip(d, 560, 560, "5", "verdicts written", ACCENT)
chip(d, 960, 560, "2", "PoC fork triggers", ORANGE)
chip(d, 1360, 560, "0", "duplicates (KV-deduped)", ACCENT)
center(d, 760, "detect  →  triage  →  verdict  —  deterministic, zero AI calls in the verdict path", REG(36), MUTED)
save(img, 5)

# 6 — SAIA writes the detections
img, d = new()
center(d, 90, "And the AI writes the detections", BOLD(68), FG)
center(d, 196, "Splunk AI Assistant (SAIA) — plain English  →  brand-new SPL, in ~21s", REG(36), MUTED)
box = [300, 290, 1620, 560]
d.rounded_rectangle(box, radius=16, fill=MONO_BG, outline=(40,52,74), width=2)
gen = ['index=omni_guard_security sourcetype="layerzero:transaction"',
       "| eventstats perc99(value_eth) as p99 by contract_name",
       "| where value_eth > 5 * p99",
       "| table _time tx_hash contract_name value_eth"]
for i, line in enumerate(gen):
    d.text((332, 322+i*54), line, font=MONO(28), fill=(167,243,208))
center(d, 660, "✓ authored live by SAIA — Splunk's own hosted model", REG(36), ACCENT)
save(img, 5)

# 7 — Fork-validation
img, d = new()
center(d, 130, "High-severity candidates are fork-validated", BOLD(60), FG)
center(d, 250, "Argus forks Ethereum mainnet with Anvil and runs a Foundry exploit test", REG(36), MUTED)
d.rounded_rectangle([700, 380, 1220, 560], radius=20, fill=CARD, outline=ACCENT, width=4)
center(d, 410, "CONFIRMED", BOLD(96), ACCENT)
center(d, 530, "only when the test's own assertions reproduce it", REG(30), MUTED)
center(d, 720, "Otherwise an honest REJECTED. It never fabricates a verdict.", REG(40), ORANGE)
save(img, 5)

# 8 — Closing
img, d = new()
center(d, 300, "Argus", BOLD(150), FG)
center(d, 500, "is what using Splunk correctly looks like.", REG(50), MUTED)
center(d, 650, "Splunk does the pattern work, holds the state,", REG(38), MUTED)
center(d, 706, "runs the agent, and writes its own detections.", REG(38), MUTED)
center(d, 860, "github.com/Alexander-Sorrell-IT/argus", MONO(38), ACCENT)
center(d, 930, "Splunk Agentic Ops Hackathon 2026  ·  AGPL-3.0", REG(30), MUTED)
save(img, 5)

# Assemble: encode each slide to its own clip, then concat the CLIPS.
# (The concat demuxer renders the first *image* black for its whole duration —
# a known ffmpeg quirk — so we concat short video clips instead, which is reliable.)
clips = []
for idx, (p, secs) in enumerate(frames):
    clip = os.path.join(OUT, f"clip_{idx:02d}.mp4")
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-loop", "1", "-t", str(secs),
                    "-i", p, "-r", "30", "-c:v", "libx264", "-preset", "veryfast",
                    "-crf", "20", "-pix_fmt", "yuv420p", "-vf", "format=yuv420p", clip],
                   check=True)
    clips.append(clip)

listf = os.path.join(OUT, "clips.txt")
with open(listf, "w") as fh:
    for c in clips:
        fh.write(f"file '{c}'\n")

total = sum(s for _, s in frames)
out_mp4 = os.path.join(os.path.dirname(os.path.abspath(__file__)), "argus_trailer.mp4")
subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-f", "concat", "-safe", "0",
                "-i", listf, "-c:v", "libx264", "-preset", "veryfast", "-crf", "20",
                "-pix_fmt", "yuv420p",
                "-vf", f"fade=t=in:st=0:d=0.5,fade=t=out:st={total-0.8:.1f}:d=0.8",
                "-movflags", "+faststart", out_mp4], check=True)
print(f"built {out_mp4}  ({len(frames)} slides, {total}s)")
