#!/usr/bin/env python3
"""Assemble the Argus demo video: honest narration (macOS `say`) timed to
dashboard screenshots with gentle Ken-Burns motion, muxed via ffmpeg."""
import os, subprocess, json, sys

DEMO = "/Users/broodierchip-m1air/Desktop/omni-guard/demo"
SHOTS = f"{DEMO}/shots"
WORK = f"{DEMO}/work"
os.makedirs(WORK, exist_ok=True)
VOICE = "Daniel"
FPS = 30

# (image, narration) — narration is HONEST and matches the live system/data.
SCENES = [
    ("00_title.png",
     "Smart contracts run for years, and there is no tail dash f for a live protocol. "
     "When something breaks, you usually hear about it on Telegram, an hour after the funds are gone. "
     "Argus turns Splunk into a security operations center for cross-chain DeFi."),
    ("01_dashboard_full.png",
     "This is Argus monitoring LayerZero, live in Splunk. Every on-chain transaction, event, "
     "source file, and audit report becomes a typed Splunk sourcetype. "
     "Hundreds of thousands of transactions indexed across in-scope contracts, overwhelmingly on Ethereum."),
    ("02_kpis.png",
     "Detection is pure S P L. Per-contract z-score outliers on transfer value and decoded token amount, "
     "with data-driven baselines plus conservative fixed floors to suppress dust and noise. The contract teaches Splunk what is normal. "
     "And Argus is honest: it separates real anomalies from ordinary protocol lifecycle. "
     "We found and disabled a rule that was flagging normal LayerZero message delivery as replay attacks. "
     "A clean baseline beats crying wolf."),
    ("03_row.png",
     "An A I agent runs inside the Splunk app itself, as a modular input on the Python S D K. "
     "It triages each finding in-process and writes its verdict back as a Splunk event, "
     "deduplicated in the K V store. Here it surfaced nine value-manipulation candidates, "
     "led by Puffer pufETH. And the detections themselves are written by Splunk's own A I: "
     "I describe a threat in plain English, and the Splunk A I Assistant writes the S P L detection "
     "for it in about fifteen seconds. The A I builds the security logic; Splunk runs it."),
    ("05_row.png",
     "High-severity candidates become proof-of-concept triggers. An external Anvil mainnet fork "
     "runs a Foundry exploit test, and Argus marks a finding confirmed only when the test's own "
     "assertions reproduce the exploit. Never on a guess, and never with a fabricated number."),
    ("99_end.png",
     "Everything runs on Splunk. Splunk does the pattern work, holds the state, runs the agent, "
     "and even writes its own detections with Splunk's hosted A I. The detections are authored by the "
     "Splunk A I Assistant, and the triage verdicts come from deterministic Splunk-native logic with zero "
     "A I calls; a local experimental model tier stays tagged in the index, but is never the production verdict. "
     "Argus is what using Splunk correctly looks like. "
     "Open source, protocol-agnostic, built for the Splunk Agentic Ops Hackathon."),
]

def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print("CMD FAILED:", " ".join(cmd[:6]), "...\n", r.stderr[-800:]); sys.exit(1)
    return r

def dur(path):
    r = run(["ffprobe","-v","quiet","-show_entries","format=duration","-of","json",path])
    return float(json.loads(r.stdout)["format"]["duration"])

scene_files, audio_files = [], []
for i,(img,text) in enumerate(SCENES):
    ip = f"{SHOTS}/{img}"
    if not os.path.exists(ip):
        print("MISSING IMAGE:", ip); sys.exit(1)
    aiff, wav = f"{WORK}/a{i}.aiff", f"{WORK}/a{i}.wav"
    run(["say","-v",VOICE,"-o",aiff,text])
    run(["ffmpeg","-y","-i",aiff,wav])
    d = dur(wav) + 0.6           # small tail pad
    audio_files.append(wav)
    # gentle ken-burns zoom on a 1920x1080 cover-scaled image
    sf = f"{WORK}/s{i}.mp4"
    frames = int(d*FPS)
    vf = (f"scale=2304:1296:force_original_aspect_ratio=increase,crop=2304:1296,"
          f"zoompan=z='min(1+0.00045*on,1.10)':d={frames}:"
          f"x='iw/2-(iw/zoom/2)':y='ih/2-(ih/zoom/2)':s=1920x1080:fps={FPS},"
          f"format=yuv420p")
    run(["ffmpeg","-y","-loop","1","-i",ip,"-t",f"{d:.2f}","-r",str(FPS),
         "-vf",vf,"-c:v","libx264","-pix_fmt","yuv420p","-preset","medium",sf])
    scene_files.append(sf)
    print(f"scene {i}: {d:.1f}s  {img}")

# concat video
with open(f"{WORK}/vlist.txt","w") as f:
    for s in scene_files: f.write(f"file '{s}'\n")
run(["ffmpeg","-y","-f","concat","-safe","0","-i",f"{WORK}/vlist.txt","-c","copy",f"{WORK}/video.mp4"])
# concat audio
with open(f"{WORK}/alist.txt","w") as f:
    for a in audio_files: f.write(f"file '{a}'\n")
run(["ffmpeg","-y","-f","concat","-safe","0","-i",f"{WORK}/alist.txt","-c","copy",f"{WORK}/audio.wav"])
# mux
out = f"{DEMO}/argus_demo.mp4"
run(["ffmpeg","-y","-i",f"{WORK}/video.mp4","-i",f"{WORK}/audio.wav",
     "-c:v","copy","-c:a","aac","-b:a","192k","-shortest",out])
print("TOTAL:", round(dur(out),1),"s  ->", out)
