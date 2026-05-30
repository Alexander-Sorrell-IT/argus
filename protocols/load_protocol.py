"""load_protocol.py — read protocols/<name>.yaml and emit the two downstream
artifacts the ARGUS pipeline consumes:

  (a) emit_scope(name)        -> the scope.json-shaped dict that
                                 ingestion/scope_loader.py expects
                                 (keys: program, contracts[].{name,address,chain_hint})

  (b) emit_config_rows(name)  -> the splunk/lookups/protocol_config.csv rows
                                 (list of (key, value) tuples, dashboard order)

This module is the SINGLE source of the YAML -> {scope, config} transform.
Swapping which YAML is loaded (e.g. PROTOCOL=aave) re-points the whole pipeline.

CLI:
    python3 protocols/load_protocol.py <name>            # human summary + scope JSON
    python3 protocols/load_protocol.py <name> --scope    # scope.json JSON to stdout
    python3 protocols/load_protocol.py <name> --config   # protocol_config.csv to stdout
    python3 protocols/load_protocol.py <name> --check     # diff against current scope.json + csv
"""
import io
import csv
import sys
import json
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.stderr.write(
        "ERROR: PyYAML is required for protocol configs "
        "(`pip install pyyaml`).\n"
    )
    raise

PROTOCOLS_DIR = Path(__file__).resolve().parent
REPO_ROOT = PROTOCOLS_DIR.parent

# Order in which protocol_config.csv emits its key,value rows. Must match the
# existing splunk/lookups/protocol_config.csv exactly for dashboard parity.
CONFIG_KEY_ORDER = [
    "protocol_name",
    "protocol_full_name",
    "protocol_tagline",
    "total_var_display",
    "total_var_usd",
    "contracts_in_scope",
    "audit_count",
    "audit_chunk_count",
    "source_files_count",
    "immunefi_program_url",
    "max_bounty_critical",
    "max_bounty_high",
]


def protocol_path(name: str) -> Path:
    """Resolve protocols/<name>.yaml (accepts 'aave' or 'example-aave')."""
    for candidate in (f"{name}.yaml", f"example-{name}.yaml", f"{name}.yml"):
        p = PROTOCOLS_DIR / candidate
        if p.exists():
            return p
    raise FileNotFoundError(
        f"No protocol config for '{name}' in {PROTOCOLS_DIR} "
        f"(looked for {name}.yaml / example-{name}.yaml)"
    )


def load_yaml(name: str) -> dict:
    return yaml.safe_load(protocol_path(name).read_text())


def _fmt(v) -> str:
    """Render a YAML scalar back to its CSV string form (no '.0' on ints,
    bools stay lowercase, None -> empty)."""
    if v is None:
        return ""
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


def emit_scope(name: str) -> dict:
    """Return the scope.json-shaped dict that scope_loader.load_scope() reads.

    scope_loader only touches `program` (unused on read) and
    `contracts[].{name,address,chain_hint}`, so we faithfully reproduce that.
    """
    data = load_yaml(name)
    contracts = []
    for c in data.get("contracts", []):
        contracts.append({
            "name": c["name"],
            "address": c["address"],
            "chain_hint": c.get("chain", c.get("chain_hint", "ethereum")),
        })
    return {
        "_doc": f"Generated from protocols/{protocol_path(name).name} "
                f"by protocols/load_protocol.py. Edit the YAML, not this.",
        "program": data.get("program", data.get("protocol_name", name)),
        "contracts": contracts,
        "commit_shas_per_contract": {
            "_doc": "TODO: per-contract commit SHA pinning"
        },
    }


def emit_config_rows(name: str) -> list[tuple[str, str]]:
    """Return the protocol_config.csv key,value rows in dashboard order."""
    data = load_yaml(name)
    display = data.get("display", {}) or {}
    rows = []
    for key in CONFIG_KEY_ORDER:
        if key in display:
            rows.append((key, _fmt(display[key])))
    return rows


def emit_config_csv(name: str) -> str:
    """Return protocol_config.csv as a string (header + rows, \\n line ends)."""
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["key", "value"])
    for k, v in emit_config_rows(name):
        w.writerow([k, v])
    return buf.getvalue()


def source_roots(name: str) -> list[str]:
    """Expanded source-code roots for ingest_source.py SOURCE_ROOTS env."""
    data = load_yaml(name)
    return [str(Path(p).expanduser()) for p in (data.get("source_roots") or [])]


def audit_path(name: str) -> str:
    """Expanded audit-text dir for ingest_audit_findings.py AUDIT_TEXT_DIR env."""
    data = load_yaml(name)
    ap = data.get("audit_path")
    return str(Path(ap).expanduser()) if ap else ""


# --------------------------------------------------------------------------- CLI
def _check(name: str) -> int:
    """Compare emitted artifacts against the current on-disk scope.json + csv."""
    ok = True

    scope_json_path = REPO_ROOT / "ingestion" / "scope.json"
    if scope_json_path.exists():
        current = json.loads(scope_json_path.read_text())
        cur_pairs = [(c["name"], c["address"].lower(), c.get("chain_hint"))
                     for c in current.get("contracts", [])]
        emitted = emit_scope(name)
        new_pairs = [(c["name"], c["address"].lower(), c["chain_hint"])
                     for c in emitted["contracts"]]
        if cur_pairs == new_pairs:
            print(f"  [OK] scope contracts match scope.json "
                  f"({len(new_pairs)} contracts)")
        else:
            ok = False
            print(f"  [FAIL] scope mismatch: "
                  f"{len(cur_pairs)} in scope.json vs {len(new_pairs)} emitted")
            for a, b in zip(cur_pairs, new_pairs):
                if a != b:
                    print(f"         scope.json: {a}\n         emitted:    {b}")
    else:
        print("  [skip] ingestion/scope.json not found")

    csv_path = REPO_ROOT / "splunk" / "lookups" / "protocol_config.csv"
    if csv_path.exists():
        current_csv = csv_path.read_text()
        emitted_csv = emit_config_csv(name)
        if current_csv.rstrip("\n") == emitted_csv.rstrip("\n"):
            print("  [OK] protocol_config.csv matches byte-for-byte")
        else:
            ok = False
            print("  [FAIL] protocol_config.csv differs:")
            cur_lines = current_csv.rstrip("\n").splitlines()
            new_lines = emitted_csv.rstrip("\n").splitlines()
            for i in range(max(len(cur_lines), len(new_lines))):
                c = cur_lines[i] if i < len(cur_lines) else "<missing>"
                n = new_lines[i] if i < len(new_lines) else "<missing>"
                if c != n:
                    print(f"         current: {c}\n         emitted: {n}")
    else:
        print("  [skip] splunk/lookups/protocol_config.csv not found")

    return 0 if ok else 1


def main(argv: list[str]) -> int:
    if not argv:
        sys.stderr.write(__doc__ or "")
        return 2
    name = argv[0]
    flags = set(argv[1:])

    if "--scope" in flags:
        print(json.dumps(emit_scope(name), indent=2))
        return 0
    if "--config" in flags:
        sys.stdout.write(emit_config_csv(name))
        return 0
    if "--check" in flags:
        print(f"Checking protocol '{name}' against current pipeline artifacts:")
        return _check(name)

    # default: human summary + the scope payload
    scope = emit_scope(name)
    rows = emit_config_rows(name)
    print(f"protocol: {name}  ({protocol_path(name).name})")
    print(f"program:  {scope['program']}")
    print(f"contracts: {len(scope['contracts'])}")
    print(f"source_roots: {len(source_roots(name))}  audit_path: {audit_path(name) or '(none)'}")
    print("display/config rows:")
    for k, v in rows:
        print(f"  {k} = {v}")
    print("\n--- scope.json payload ---")
    print(json.dumps(scope, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
