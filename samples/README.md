# Argus — runnable sample dataset

This folder makes the repo **runnable from a fresh clone**. The live data the
project normally ingests is gitignored, so without this bundle a fresh clone
has nothing to detect on. These files are a small, representative slice of the
real `omni_guard_security` index — enough to make the detections actually fire.

## What's here

| File | Records | Loads into |
|------|--------:|------------|
| `layerzero_transaction.jsonl` | 408 | `sourcetype=layerzero:transaction` |
| `layerzero_event.jsonl` | 400 | `sourcetype=layerzero:event` |
| `contract_baselines.kv.json` | 13 | KV collection `contract_baselines` |
| `load_samples.sh` | — | the loader script |

Each `.jsonl` line is one original `_raw` event (JSON), so it **re-indexes
identically** to the live data — same fields, same extractions, same
timestamps. The transaction sample is deliberately composed: it contains the
value-transfer **outliers** the detections fire on, plus normal baseline
traffic from the same contracts for realistic context. The event sample
includes ERC-20 Transfer events whose amounts trip the Token Transfer Outlier
rule. The KV snapshot is the full per-contract baseline table the
lookup-driven detections join against.

## Run on a fresh clone

**1. (Recommended) Install the `omni_guard` Splunk app** so the sourcetypes,
index, and KV collection definition exist:

```bash
cp -r <repo>/splunk "$SPLUNK_HOME/etc/apps/omni_guard"
"$SPLUNK_HOME/bin/splunk" restart
```

(If you skip this, `load_samples.sh` will best-effort create the index and KV
collection itself, but installing the app gives full field-extraction
fidelity.)

**2. Load the sample data + baselines:**

```bash
cd samples
SPLUNK_HOME=/Applications/Splunk SPLUNK_USER=admin ./load_samples.sh
# (you'll be prompted for the password, or set SPLUNK_PASS=...)
```

The script `splunk add oneshot`s the two JSONL files into the
`omni_guard_security` index and `batch_save`s the baselines into the
`contract_baselines` KV collection. (It falls back to HEC if the `splunk` CLI
isn't available — set `HEC_URL` / `HEC_TOKEN`.)

**3. Verify the detections fire — search over ALL TIME (`earliest=0`).**

> The sample events carry their **original historical timestamps**, so the
> default real-time / last-15-minutes window finds nothing. Use the **All time**
> time-range picker, or `earliest=0 latest=now` in the SPL.
>
> Also give the oneshot ingest ~15-30s to finish becoming searchable before you
> judge the result — the high-value outlier records commit slightly after the
> bulk of the data, so a search run immediately after loading may show only a
> handful of outliers. Re-run once `... | stats count` stabilizes.

```
index=omni_guard_security sourcetype=layerzero:transaction value_eth>0 earliest=0 latest=now
| lookup contract_baselines contract_name OUTPUT mean_value_eth, stdev_value_eth, tx_count_30d
| where isnotnull(mean_value_eth) AND tx_count_30d>=30 AND stdev_value_eth>0
| eval zscore=(value_eth-mean_value_eth)/stdev_value_eth
| where zscore>3 AND value_eth>0.1
| eval severity=case(zscore>10,"CRITICAL", zscore>5,"HIGH", true(),"MEDIUM")
| stats count by contract_name, severity
```

On this sample that yields **~96 value-transfer outliers** across 5 contracts
(BTC.b OFT wrapper, Puffer pufETH, USDT0, Swell rswETH, UltraLightNodeV2),
including CRITICAL and HIGH severities. The `Argus - Token Transfer Outlier`
saved search likewise fires on the event sample (BTC.b and Renzo ezETH).

You can also just run the bundled saved searches from the app
(`Argus - Value Outlier Fast`, `Argus - Token Transfer Outlier`, etc.) over
All time.

## Note on data age

The index ships with `frozenTimePeriodInSecs = 7776000` (90 days) and these
sample events are timestamped ~June 2026. If you load this bundle more than
~90 days later, the events would age past the frozen window on ingest. In that
case either raise `frozenTimePeriodInSecs` in the app's `indexes.conf` before
loading, or accept that older buckets may roll to frozen. (Within the judging
window this is a non-issue.)

## Note on the AI agent

**SAIA (the in-app Argus AI agent / SPL authoring) needs a Splunk Cloud
tenant; everything else here runs offline on this sample.** The detections,
baselines, KV lookups, and severity scoring all run on a local/standalone
Splunk with no external model — only the SAIA reasoning path requires Cloud.
