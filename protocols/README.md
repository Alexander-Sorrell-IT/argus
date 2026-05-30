# protocols/ — protocol-agnostic config layer

ARGUS monitors a protocol by reading one human-authored YAML. Drop a
`protocols/<name>.yaml`, set `PROTOCOL=<name>`, and the scan/ingest/detection
**scope** re-points at that protocol at runtime with **no code change**. The
dashboard metadata lookup (`protocol_config.csv`) is a **generated artifact** —
the YAML is its source of truth, but it is a static file, so regenerate it with
`--config` when you swap (the scope re-points live; the CSV does not).

## How it works

`load_protocol.py` is the single source of the YAML → pipeline transform. From
one `<name>.yaml` it emits the two artifacts downstream consumers already expect:

| Emitted artifact            | Shape                                              | Consumed by                                  |
|-----------------------------|----------------------------------------------------|----------------------------------------------|
| scope.json-shaped dict      | `{program, contracts[].{name,address,chain_hint}}` | `ingestion/scope_loader.py` → all scan/ingest |
| `protocol_config.csv` rows  | `key,value` rows (dashboard order)                 | `splunk/lookups/protocol_config.csv` lookup   |

`ingestion/scope_loader.py` checks the `PROTOCOL` env var:

- **`PROTOCOL` unset** → reads `ingestion/scope.json` exactly as before
  (no PyYAML dependency on this path).
- **`PROTOCOL=<name>`** → reads `protocols/<name>.yaml` via `load_protocol.py`.

Source-code and audit roots are wired through env vars the ingest scripts read:
`SOURCE_ROOTS` (in `ingest_source.py`) and `AUDIT_TEXT_DIR`
(in `ingest_audit_findings.py`).

## Swap a protocol

```bash
# Default — LayerZero, unchanged (no PROTOCOL set, reads scope.json):
python ingestion/historical_scan.py

# LayerZero via the new YAML path (reproduces scope.json exactly):
PROTOCOL=layerzero python ingestion/historical_scan.py

# A different protocol — re-points the entire SCAN at Aave's contract set:
PROTOCOL=aave python ingestion/historical_scan.py

# Re-point the DASHBOARD too — the CSV lookup is generated, not auto-swapped:
python protocols/load_protocol.py aave --config > splunk/lookups/protocol_config.csv
```

To also point source/audit ingestion at a protocol's roots, export what the
loader resolves from the YAML:

```bash
export SOURCE_ROOTS="$(python protocols/load_protocol.py aave --scope >/dev/null; \
  python -c 'import sys; sys.path.insert(0,"protocols"); import load_protocol; \
  print(":".join(load_protocol.source_roots("aave")))')"
export AUDIT_TEXT_DIR="$(python -c 'import sys; sys.path.insert(0,"protocols"); \
  import load_protocol; print(load_protocol.audit_path("aave"))')"
PROTOCOL=aave python ingestion/ingest_source.py
```

## Inspect / verify a config

```bash
python protocols/load_protocol.py layerzero            # human summary + scope JSON
python protocols/load_protocol.py layerzero --scope    # emit scope.json JSON
python protocols/load_protocol.py layerzero --config   # emit protocol_config.csv
python protocols/load_protocol.py layerzero --check    # diff vs current scope.json + csv
```

`--check` on `layerzero` confirms the YAML reproduces the current pipeline
byte-for-byte (contract list == `scope.json`, config rows == `protocol_config.csv`).

## Add a new protocol

1. Copy `layerzero.yaml` → `protocols/<name>.yaml`.
2. Fill in `program`, the `display` block (dashboard metadata), `source_roots`,
   `audit_path`, and the `contracts` list.
3. `python protocols/load_protocol.py <name>` to sanity-check the emitted scope.
4. `PROTOCOL=<name> python ingestion/historical_scan.py`.

## Files

- `layerzero.yaml` — the live LayerZero config; reproduces `scope.json` +
  `protocol_config.csv` exactly (verified via `--check`).
- `example-aave.yaml` — a small, real Aave V3 mainnet contract set proving the
  swap is live. Illustrative subset; full Aave ingestion not run.
- `load_protocol.py` — the YAML → {scope, config} loader.

## What is proven vs scaffolded

- **Proven:** `load_protocol.py layerzero --check` reproduces the current
  `scope.json` contracts and `protocol_config.csv` rows exactly; `PROTOCOL=aave`
  makes `scope_loader.load_scope()` (the live consumer used by `historical_scan`
  and `ingest_transactions`) return a different, non-empty scope; the default
  (`scope.json`) path is unchanged and works even with PyYAML uninstalled; an
  unknown `PROTOCOL` fails loudly instead of silently scanning LayerZero.
- **Generated, not auto-re-pointed:** the **scope** is read from the YAML at
  runtime (true live swap), but `protocol_config.csv` is a static Splunk lookup —
  the YAML is its source of truth via `--config`, yet a `PROTOCOL` swap does NOT
  rewrite the CSV by itself. Regenerate it (`--config > …/protocol_config.csv`)
  when you swap, or the dashboard keeps showing the previous protocol's numbers.
- **Scaffolded:** a full second-protocol (Aave) end-to-end ingestion has not
  been run, and source/audit-root re-pointing is via env vars you export
  manually (`SOURCE_ROOTS`, `AUDIT_TEXT_DIR`) rather than auto-applied by
  `PROTOCOL`. The config layer is genuinely protocol-agnostic; only the live
  data pull for a non-LayerZero protocol remains unproven.
