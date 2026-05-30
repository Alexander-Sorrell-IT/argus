"""ingest_source.py — push LayerZero Solidity source code into Splunk as
sourcetype layerzero:source. One event per .sol file with extracted
contract/function/event signatures so the AI can find code by symbol.

Skips test/mock/sample files to keep the corpus relevant.
"""
import os, re, sys, time, hashlib, logging
from pathlib import Path
from dotenv import load_dotenv
from splunk_hec import SplunkHEC

load_dotenv()
logging.basicConfig(level=os.getenv("LOG_LEVEL","INFO"),
                    format="%(asctime)s  %(levelname)-8s  %(message)s")
log = logging.getLogger(__name__)

# SRC_ROOTS — override via SOURCE_ROOTS env (colon-separated) when monitoring a
# different protocol. Defaults are the LayerZero demo paths.
_default_roots = [
    Path.home()/"Desktop/omni-guard/layerzero-src/LayerZero",
    Path.home()/"Desktop/omni-guard/layerzero-src/LayerZero-v2",
    Path.home()/"Desktop/omni-guard/layerzero-src/solidity-examples",
]
SRC_ROOTS = (
    [Path(p) for p in os.getenv("SOURCE_ROOTS", "").split(":") if p]
    or _default_roots
)
# Skip patterns — test/mock/sample noise
SKIP_RE = re.compile(r"(?i)(/test/|/tests/|/mocks?/|/sample/|/example/|\.t\.sol$|Mock\w*\.sol$|Test\w*\.sol$|Sample\w*\.sol$)")
MAX_FILE_CHARS = 60_000   # cap per file — bigger gets chunked

# Regex extractors (good enough; not a real parser, just for symbol indexing)
CONTRACT_RE = re.compile(r"^\s*(abstract\s+)?(contract|interface|library)\s+(\w+)", re.MULTILINE)
FUNCTION_RE = re.compile(r"^\s*function\s+(\w+)\s*\(([^)]*)\)\s*([^{;]*)", re.MULTILINE)
EVENT_RE    = re.compile(r"^\s*event\s+(\w+)\s*\(([^)]*)\)", re.MULTILINE)
MODIFIER_RE = re.compile(r"^\s*modifier\s+(\w+)\s*\(([^)]*)\)", re.MULTILINE)
PRAGMA_RE   = re.compile(r"^\s*pragma\s+solidity\s+([^;]+);", re.MULTILINE)

def extract_symbols(src: str) -> dict:
    return {
        "pragma":        (PRAGMA_RE.findall(src) or [""])[0].strip(),
        "contracts":     [m[2] for m in CONTRACT_RE.findall(src)],
        "functions":     [m[0] for m in FUNCTION_RE.findall(src)],
        "events":        [m[0] for m in EVENT_RE.findall(src)],
        "modifiers":     [m[0] for m in MODIFIER_RE.findall(src)],
        "function_sigs": [f"{m[0]}({m[1].strip()})" for m in FUNCTION_RE.findall(src)],
        "event_sigs":    [f"{m[0]}({m[1].strip()})" for m in EVENT_RE.findall(src)],
    }

def build_event(path: Path, src: str, root: Path) -> dict:
    rel = path.relative_to(root)
    sym = extract_symbols(src)
    return {
        "timestamp":      int(path.stat().st_mtime),
        "repo":           root.name,
        "rel_path":       str(rel),
        "file_name":      path.name,
        "file_size":      len(src),
        "sha256":         hashlib.sha256(src.encode()).hexdigest()[:16],
        "pragma":         sym["pragma"],
        "contracts":      sym["contracts"],
        "functions":      sym["functions"],
        "events":         sym["events"],
        "modifiers":      sym["modifiers"],
        "function_sigs":  sym["function_sigs"],
        "event_sigs":     sym["event_sigs"],
        "n_contracts":    len(sym["contracts"]),
        "n_functions":    len(sym["functions"]),
        "source_code":    src[:MAX_FILE_CHARS],
        "truncated":      len(src) > MAX_FILE_CHARS,
    }

def main():
    files = []
    for root in SRC_ROOTS:
        if not root.exists():
            log.warning(f"skip missing root: {root}")
            continue
        for p in root.rglob("*.sol"):
            if SKIP_RE.search(str(p)):
                continue
            files.append((p, root))

    log.info(f"Indexing {len(files)} Solidity files from {len(SRC_ROOTS)} roots")
    sent = 0
    skipped = 0
    with SplunkHEC() as hec:
        for i, (path, root) in enumerate(files, 1):
            try:
                src = path.read_text(encoding="utf-8", errors="ignore")
            except Exception as e:
                log.warning(f"  skip read fail {path}: {e}")
                skipped += 1
                continue
            if len(src) < 50:
                skipped += 1
                continue
            ev = build_event(path, src, root)
            hec.send(ev, sourcetype="layerzero:source")
            sent += 1
            if i % 50 == 0:
                log.info(f"  {i}/{len(files)} indexed ({sent} sent, {skipped} skipped)")
        hec.flush()
    log.info(f"Done — {sent} source files indexed, {skipped} skipped")

if __name__ == "__main__":
    main()
