# Public release checklist — Argus

Argus is an open-source, Splunk-native security operations platform for
cross-chain DeFi (demo target: LayerZero). This checklist covers publishing
the public repo for the hackathon submission.

Guiding principle: **this is an open-source hackathon entry, so we SHIP the
real system.** Judges need to read the detections, the agent, and the fork
validator and see that they do what we claim. We only withhold three classes of
thing: (1) secrets, (2) real/operator-private findings data, and (3) the
deprecated/never-activated roadmap code. We do **not** hide working detections.

## What we ship (the real system)

- **Every saved search** in `splunk/default/savedsearches.conf` — all of them,
  renamed from the legacy `OmniGuard - …` prefix to `Argus - …`. That means the
  ~14 detections *and* the two utility searches (`Build Contract Baselines`,
  `Candidate Scoring`) that earlier drafts wanted to withhold. Nothing in this
  file stays behind. They are the core of the project — eventstats z-score,
  streamstats, predict, cluster, MLTK DBSCAN, plus the `contract_baselines`
  kvstore lookups. Hiding any of them would be self-sabotage for an open-source
  judging round.
- The **live agent**: `splunk/bin/argus_agent.py` (Splunk modular input,
  deterministic Splunk-native tier-0 triage; `reasoning_engine=splunk_native_tier0`).
- The **fork validator**: `poc/validate_finding.py` (Anvil fork at block N-1 +
  Foundry test, writes honest `CONFIRMED`/`REJECTED` to `layerzero:fork_result`).
- Splunk app config: `props.conf`, `transforms.conf`, `collections.conf`,
  `indexes.conf`, `inputs.conf`, `savedsearches.conf`.
- `architecture.png` and `ARCHITECTURE.md` (required deliverables).
- README, PROJECT_OVERVIEW, DEMO_SCRIPT, `.env.example`, `requirements.txt`.

## Files that MUST NOT ship to public

These are excluded by `.gitignore` (verify with `git check-ignore <path>`):

| File / dir | Why it's out |
|---|---|
| `.env` (and any `.env.*` except `.env.example`) | Secrets / API keys |
| `*.lic`, `*.pem`, `*.key` | Credentials |
| `poc/findings/` contents (except `.gitkeep`) | Real candidate findings + operator data |
| `poc/findings/*/{out,cache,lib}/` | Foundry build artifacts (bloat) |
| `logs/` | Runtime data + findings feed |
| `layerzero-src/`, `agent/audit_text/`, `models/` | Large vendored corpora — documented in README, regenerated locally |
| `agent/submission_template.py`, `agent/foundry_gen.py` | Offensive automation — kept on the private branch |
| `splunk/lookups/bad_addresses.csv` | Full curated list — ship a small public stub instead |
| `agent/mcp_agent.py` | **DEPRECATED** MCP-over-SSE orchestrator — not the live loop (live agent is `splunk/bin/argus_agent.py`) |
| `agent/splunk_mcp_client.py` | **KEEP — LIVE.** This is the SAIA client (`generate_spl`/`explain_spl` via `/predict`); `agent/saia_generate_detection.py` depends on it. Do **not** exclude. |
| `splunk-mcp/`, `bug-hunter/` | Deprecated custom MCP server / personal scratch |
| `demo/work/`, `demo/shots/`, `demo/voice/` | Render scratch dirs |
| `demo/argus_demo.mp4`, `demo/argus_trailer.mp4`, `demo/mermaid.min.js` | Large render artifacts (host the video externally; link in README) |

## Pre-publish steps

1. **Rename detections** `OmniGuard - …` → `Argus - …` in
   `splunk/default/savedsearches.conf` (the app labels are already `Argus`).
2. **Ship a stub** `splunk/lookups/bad_addresses.csv` with ~3 famous public
   entries (e.g. known mixer / sanctioned addresses) so detections that depend
   on it run out of the box; keep the full curated list on the private branch.
3. **Empty the kvstore** `contract_baselines` collection before bundling the app
   for distribution (it holds operator-accumulated baselines). The collection
   schema in `collections.conf` ships; the data does not.
4. **Defensive framing** in README/dashboards: position as a SOC for cross-chain
   protocols. Remove bug-bounty / submission-generation language. Demo wording:
   "alert the operations team."
5. **Confirm the AI claim is precise**: the verdict path is deterministic and
   makes zero AI calls; the only LLM in the production loop is Splunk's own hosted
   **SAIA**, which authors/explains the SPL detections (live, verified). No
   third-party model sits in the verdict path. SAIA free-form finding-*judgment*
   (`agent/llm_enrich.py`) is experimental (deflects/times out for this tenant) and
   is **not** in the verdict path. An experimental local-MLX tier (Qwen2.5 /
   Foundation-Sec) stays roadmap — its rows remain tagged in the `ai_report` index
   (`reasoning_engine`) but it is never the production verdict.

## Verify exclusions before pushing

```bash
# After 'git add -A', list everything staged for the public repo and confirm
# none of the private paths are present (.env.example is intentionally kept):
git ls-files --cached | grep -E '^(\.env$|\.env\.[^/]+$|logs/|poc/findings/|layerzero-src/|models/|agent/(mcp_agent|foundry_gen|submission_template)\.py|demo/(work|shots|voice)/|demo/.*\.mp4|demo/mermaid\.min\.js)' \
  | grep -v '^\.env\.example$'
# ^ this must print NOTHING. If it prints a path, it is about to ship — stop.

# architecture.png MUST NOT be ignored (required deliverable). Empty output = good:
git check-ignore architecture.png && echo "PROBLEM: architecture.png is ignored" || echo "OK: architecture.png will ship"
```

## License

Public ships under **AGPL-3.0** (`LICENSE`,
`Copyright (C) 2026 Alexander Sorrell — Argus`). A commercial license is
available — note this in the README header.

## Publish with `gh` (GitHub CLI)

The old manual "create a repo in the browser, add a remote, push" dance is
gone. Use `gh`:

```bash
cd /Users/broodierchip-m1air/Desktop/omni-guard

# 0. Untrack the deprecated MCP orchestrator. It is gitignored, but git keeps
#    tracking files that were committed before the ignore rule existed. This
#    removes it from the index (the file stays on disk) so it does not ship.
#    The leak-grep in "Verify exclusions" above flags it while still tracked;
#    that is your reminder to run this step. (splunk_mcp_client.py SHIPS — it is
#    the live SAIA client; do NOT untrack it.)
git rm --cached agent/mcp_agent.py

# 1. Stage everything and sanity-check (re-run the leak-grep from "Verify").
git add -A
git status

# 2. Commit the public-ready state.
git commit -m "Argus: public hackathon release"

# 3. Create the public repo on GitHub and push in one shot.
#    --source=. uses this repo; --push pushes the current branch.
gh repo create argus --public \
  --source=. \
  --remote=origin \
  --description="Splunk-native security operations for cross-chain DeFi (LayerZero demo)" \
  --push

# 4. Confirm what actually landed on the remote (final guard against leaks).
gh repo view --web
```

If the repo already exists, skip `gh repo create` and just
`git push -u origin <branch>`.

## Submit

Copy the repo URL from `gh repo view --json url --jq .url` (and the externally
hosted demo video link) into the Devpost submission.
