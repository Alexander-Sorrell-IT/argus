"""One-time extraction: turn each audit PDF into a parallel .txt file.

Builds ~/Desktop/omni-guard/agent/audit_text/<category>/<pdf-name>.txt
Resumable — skips files that already have a non-empty .txt next to them.
"""
import sys, time
from pathlib import Path
import pdfplumber

SRC = Path.home() / "Desktop/omni-guard/layerzero-src/Audits/audits"
DST = Path.home() / "Desktop/omni-guard/agent/audit_text"

def extract(pdf_path: Path, out_path: Path) -> int:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with pdfplumber.open(pdf_path) as pdf:
            parts = []
            for i, page in enumerate(pdf.pages):
                t = page.extract_text() or ""
                parts.append(t)
            text = "\n\n".join(parts)
        out_path.write_text(text, encoding="utf-8")
        return len(text)
    except Exception as e:
        out_path.write_text(f"[EXTRACT_ERROR] {e}", encoding="utf-8")
        return -1

def main():
    pdfs = sorted(SRC.rglob("*.pdf"))
    print(f"Found {len(pdfs)} PDFs under {SRC}")
    total_chars = 0
    extracted = 0
    skipped = 0
    failed = 0
    t0 = time.time()
    for i, pdf in enumerate(pdfs, 1):
        rel = pdf.relative_to(SRC)
        out = DST / rel.with_suffix(".txt")
        if out.exists() and out.stat().st_size > 100:
            skipped += 1
            continue
        n = extract(pdf, out)
        if n > 0:
            extracted += 1
            total_chars += n
            print(f"  [{i}/{len(pdfs)}] {rel} → {n:,} chars")
        else:
            failed += 1
            print(f"  [{i}/{len(pdfs)}] {rel} FAILED")
    dt = time.time() - t0
    print(f"\nDone in {dt:.1f}s — extracted {extracted}, skipped {skipped}, failed {failed}, total {total_chars:,} chars")

if __name__ == "__main__":
    main()
