# Public release checklist — Argus

Before publishing the public repo for the hackathon submission, run through
this checklist to ensure no proprietary tuning, offensive automation, or
private data leaks into the public version.

## Files that MUST NOT ship to public

| File / dir | Why it's private | Status |
|---|---|---|
| `.env` (and any `.env.*` except `.env.example`) | Secrets | gitignored |
| `poc/findings/` contents | Real candidate findings (and any real bugs) | gitignored |
| `agent/submission_template.py` | Auto-generates Immunefi submissions — offensive automation | gitignored |
| `agent/foundry_gen.py` | Auto-generates exploit tests from Claude/SAIA — offensive automation | gitignored |
| `splunk/lookups/bad_addresses.csv` | Full curated list. Ship a stub with 3 famous public entries instead. | gitignored; ship `bad_addresses.example.csv` |
| `logs/` | Runtime data + findings feed | gitignored |
| `layerzero-src/` | 290 MB vendored source + 228 MB audits. Document where to get it; don't ship. | gitignored |
| `agent/audit_text/` | Extracted audit text. Document the regen process; don't ship. | gitignored |
| `bug-hunter/` | Personal scratch work | gitignored |

## Saved searches: ship subset only

`splunk/default/savedsearches.conf` contains 13 searches. Public ship list:

**Ship (4):**
- `OmniGuard - Value Transfer Outlier` (the vanilla version, not the kvstore one)
- `OmniGuard - Failed Transaction Burst vs Baseline`
- `OmniGuard - Cross-Contract Sender Correlation`
- `OmniGuard - VaR Exposure Summary`

**Hide (9):**
- `OmniGuard - Sender Behavior Outlier` (tuned thresholds)
- `OmniGuard - Replay or Duplicate Message ID` (tuned dedup window)
- `OmniGuard - Rare Transaction Pattern Cluster` (tuned similarity)
- `OmniGuard - Multi-Step Attack Sequence` (tuned maxspan/maxpause)
- `OmniGuard - Tx Volume Forecast Deviation` (predict tuning)
- `OmniGuard - Known-Bad Address Touched` (depends on private CSV)
- `OmniGuard - Value Outlier Fast` (depends on kvstore baselines)
- `OmniGuard - Build Contract Baselines` (proprietary baseline approach)
- `OmniGuard - Candidate Scoring` (proprietary scoring weights)
- `OmniGuard - Source Risk Pattern Scan` (proprietary risk-pattern set)
- `OmniGuard - Sender Behavior Clustering` (proprietary feature set + DBSCAN params)

Process: maintain `splunk/default/savedsearches.public.conf` with the 4
ship-list searches; rename to `savedsearches.conf` when publishing.

## Foundry templates: ship 1, hide 4

Ship `ValueExtraction.t.sol` only as a demo of the validator pattern.
Hide `Replay.t.sol`, `DvnBypass.t.sol`, `AdminKeyGrant.t.sol`, `Reentrancy.t.sol`.

## kvstore: empty before publish

`/Applications/Splunk/etc/apps/omni_guard/collections.conf` defines the
`contract_baselines` collection. The data inside is yours from months of
running — clear it before bundling the app for distribution.

## README + dashboards: defensive framing only

- Position as "SOC for cross-chain protocols"
- Remove any mention of Immunefi, bug bounty, $15M, submission generation
- Demo language: "alert the operations team"; not "submit privately"

## License

Public ships under **AGPL-3.0**. Add `LICENSE` file with the AGPL-3.0 text.
README header notes: *"Commercial license available — contact author"*.

## Process to actually publish

1. Make a clean branch: `git checkout -b public-release`
2. Verify `.gitignore` excludes everything in the table above
3. Rename `savedsearches.conf` → `savedsearches.private.conf` (keep locally)
4. Rename `savedsearches.public.conf` → `savedsearches.conf` (ship this one)
5. Generate `splunk/lookups/bad_addresses.csv` from 3 famous public entries
6. Clear `kvstore` collections
7. Update `LICENSE` to AGPL-3.0
8. Commit; push to a fresh public GitHub repo
9. Submit URL to Devpost
