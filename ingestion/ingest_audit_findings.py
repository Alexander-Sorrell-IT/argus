"""ingest_audit_findings.py — turn extracted audit text into queryable
Splunk events under sourcetype layerzero:audit_finding.

Source: ~/Desktop/omni-guard/agent/audit_text/<category>/<file>.txt
        (already extracted from PDFs by agent/extract_audits.py)

Strategy:
  - Walk every .txt
  - Split into ~2k-char overlapping chunks (audit findings are paragraph-sized)
  - Per chunk, extract: severity label, mentioned contracts, finding number,
    auditor, audit date, vuln-class keywords
  - Ship each chunk as one event

After this runs, audit cross-reference becomes a pure SPL query — no Python
grep at runtime. The agent can ask `sourcetype=layerzero:audit_finding` like
any other indexed dataset.
"""
import os, re, hashlib, logging
from pathlib import Path
from datetime import datetime
from dotenv import load_dotenv
from splunk_hec import SplunkHEC

load_dotenv()
logging.basicConfig(level=os.getenv("LOG_LEVEL","INFO"),
                    format="%(asctime)s  %(levelname)-8s  %(message)s")
log = logging.getLogger(__name__)

AUDIT_TEXT_DIR = Path.home() / "Desktop/omni-guard/agent/audit_text"
CHUNK_CHARS    = 2000
OVERLAP_CHARS  = 200

# Parse filenames like "DVN-Zellic-25AUG2023.pdf" or "EndpointV2-Certora-DEC2023.pdf"
FNAME_RE = re.compile(r"^([^-]+)-([^-]+)-(\d{1,2}[A-Z]{3,9}\d{2,4}|[A-Z]{3,9}\d{2,4})", re.IGNORECASE)

# Severity labels auditors use
SEV_RE = re.compile(r"\b(Critical|High|Medium|Low|Informational|Info)\b", re.IGNORECASE)

# Contract-name patterns we care about (matches against text body)
KNOWN_CONTRACTS = [
    "UltraLightNodeV2", "UltraLightNode", "Endpoint", "EndpointV1", "EndpointV2",
    "SendULN302", "ReceiveULN302", "SendULN301", "ReceiveULN301", "ULN",
    "DVN", "MessageLib", "OFT", "OApp", "ONFT", "ZRO", "Relayer", "Treasury",
    "FPValidator", "Executor", "PriceFeed", "Stargate",
]

VULN_KEYWORDS = {
    "replay_attack":       ["replay", "duplicate message", "nonce reuse", "message id"],
    "admin_key_change":    ["transferOwnership", "renounceOwnership", "setOwner",
                            "centralization risk", "owner privilege"],
    "dvn_bypass":          ["dvn bypass", "verifier bypass", "skip verification",
                            "uln bypass", "quorum bypass"],
    "reentrancy":          ["reentrancy", "reentrant", "checks-effects"],
    "access_control":      ["access control", "missing modifier", "unauthorized"],
    "integer_overflow":    ["overflow", "underflow", "unchecked math"],
    "front_running":       ["front-running", "frontrun", "mev", "sandwich"],
    "denial_of_service":   ["denial of service", "dos", "out of gas", "unbounded loop"],
    "fee_manipulation":    ["fee bypass", "fee underflow", "underpriced"],
    "oracle_manipulation": ["oracle manipulation", "stale price", "price manipulation"],
    "logic_error":         ["incorrect logic", "wrong calculation", "off-by-one"],
}


def parse_filename(name: str) -> tuple[str, str, str]:
    """Return (contract_hint, auditor, audit_date) from a filename stem."""
    base = name.replace(".txt","").replace(".pdf","")
    m = FNAME_RE.match(base)
    if m:
        return m.group(1).strip(), m.group(2).strip(), m.group(3).strip()
    parts = re.split(r"[-_ ]", base)
    return (parts[0] if parts else base), "", ""


def parse_date_to_iso(s: str) -> str:
    """Best-effort: '25AUG2023' or 'AUG2023' or '14MAR2024' -> ISO yyyy-mm-dd."""
    if not s:
        return ""
    for fmt in ("%d%b%Y", "%b%Y", "%d%B%Y", "%B%Y"):
        try:
            return datetime.strptime(s.upper().replace("SEP","SEP").replace("SEPT","SEP"),
                                     fmt.upper()).date().isoformat()
        except ValueError:
            continue
    return s


def extract_contracts(text: str) -> list[str]:
    out = set()
    low = text.lower()
    for c in KNOWN_CONTRACTS:
        if c.lower() in low:
            out.add(c)
    return sorted(out)


def extract_vuln_classes(text: str) -> list[str]:
    out = set()
    low = text.lower()
    for vc, kws in VULN_KEYWORDS.items():
        if any(k in low for k in kws):
            out.add(vc)
    return sorted(out)


def extract_severities(text: str) -> list[str]:
    found = SEV_RE.findall(text)
    return sorted({s.title().replace("Info", "Informational") for s in found})


def chunk(text: str) -> list[str]:
    """Sliding-window chunks. Cheap, deterministic."""
    chunks = []
    n = len(text)
    i = 0
    while i < n:
        end = min(i + CHUNK_CHARS, n)
        chunks.append(text[i:end])
        if end == n:
            break
        i = end - OVERLAP_CHARS
    return chunks


def main():
    files = sorted(AUDIT_TEXT_DIR.rglob("*.txt"))
    log.info(f"Indexing {len(files)} extracted audit files into Splunk")
    total_chunks = 0
    with SplunkHEC() as hec:
        for i, p in enumerate(files, 1):
            rel = p.relative_to(AUDIT_TEXT_DIR)
            category = rel.parts[0] if rel.parts else ""
            contract_hint, auditor, audit_date = parse_filename(p.name)
            audit_date_iso = parse_date_to_iso(audit_date)
            try:
                txt = p.read_text(encoding="utf-8", errors="ignore")
            except Exception as e:
                log.warning(f"  skip {rel}: {e}")
                continue
            if len(txt) < 200 or txt.startswith("[EXTRACT_ERROR]"):
                continue
            for j, ch in enumerate(chunk(txt)):
                ev = {
                    "timestamp":    int(p.stat().st_mtime),
                    "category":     category,
                    "audit_file":   str(rel),
                    "file_name":    p.name,
                    "auditor":      auditor,
                    "audit_date":   audit_date,
                    "audit_date_iso": audit_date_iso,
                    "contract_hint": contract_hint,
                    "chunk_index":  j,
                    "chunk_count":  None,   # filled at end if needed
                    "chunk_sha":    hashlib.sha256(ch.encode()).hexdigest()[:16],
                    "severities":   extract_severities(ch),
                    "contracts":    extract_contracts(ch),
                    "vuln_classes": extract_vuln_classes(ch),
                    "excerpt":      ch,
                    "excerpt_len":  len(ch),
                }
                hec.send(ev, sourcetype="layerzero:audit_finding")
                total_chunks += 1
            if i % 20 == 0:
                log.info(f"  {i}/{len(files)} files indexed, {total_chunks} chunks so far")
        hec.flush()
    log.info(f"Done — {len(files)} audits, {total_chunks} chunks indexed as layerzero:audit_finding")

if __name__ == "__main__":
    main()
