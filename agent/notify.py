"""notify.py — fire local + persistent notifications when something
important happens (CONFIRMED finding, escalation, etc).

Two channels:
  1. macOS Notification Center via osascript (immediate visual ping)
  2. ~/Desktop/omni-guard/logs/findings_feed.log append-only watch file
     (durable log; `tail -f` to follow from a terminal)
"""
from __future__ import annotations
import os, subprocess, datetime, logging
from pathlib import Path

log = logging.getLogger(__name__)
REPO     = Path(__file__).resolve().parents[1]
FEED_LOG = REPO / "logs" / "findings_feed.log"


def notify_macos(title: str, message: str, subtitle: str = "OmniGuard"):
    """Fire a macOS Notification Center banner. Silent on other platforms."""
    if not _is_macos():
        return
    # Escape double quotes for AppleScript
    t = title.replace('"', '\\"')
    s = subtitle.replace('"', '\\"')
    m = message.replace('"', '\\"')[:240]
    script = f'display notification "{m}" with title "{t}" subtitle "{s}" sound name "Frog"'
    try:
        subprocess.run(["osascript", "-e", script], timeout=5, check=False)
    except Exception as e:
        log.debug(f"notify_macos failed: {e}")


def append_feed(text: str):
    """Append a timestamped line to the findings feed log."""
    try:
        FEED_LOG.parent.mkdir(parents=True, exist_ok=True)
        ts = datetime.datetime.now().isoformat(timespec="seconds")
        with FEED_LOG.open("a", encoding="utf-8") as f:
            f.write(f"[{ts}] {text}\n")
    except Exception as e:
        log.debug(f"append_feed failed: {e}")


def confirmed_finding(finding_id: str, contract_name: str, vuln_class: str,
                      attacker_gain_eth: float = 0.0, submission_path: str = ""):
    """Announce a confirmed finding."""
    title = "🚨 OmniGuard — Confirmed Finding"
    msg = f"{contract_name}: {vuln_class}"
    if attacker_gain_eth > 0:
        msg += f" (attacker +{attacker_gain_eth:.4f} ETH on fork)"
    notify_macos(title, msg)
    feed = (f"CONFIRMED {finding_id} | {contract_name} | {vuln_class}"
            f" | attacker_gain={attacker_gain_eth:.6f} ETH")
    if submission_path:
        feed += f" | submission: {submission_path}"
    append_feed(feed)


def escalation(finding_id: str, summary: str, severity: str = "HIGH"):
    """Lower-priority signal: finding hit deep investigation but not yet validated."""
    title = f"OmniGuard — Escalation ({severity})"
    notify_macos(title, summary[:240])
    append_feed(f"ESCALATION {finding_id} | {severity} | {summary[:200]}")


def _is_macos() -> bool:
    import platform
    return platform.system() == "Darwin"
