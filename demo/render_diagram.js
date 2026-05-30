// render_diagram.js — render the AS-BUILT Argus architecture diagram to PNG.
//
// mermaid-cli won't install (node v20.0.0 breaks npm), so we drive a real
// headless Chromium via Playwright: setContent an HTML shell, inject a LOCAL
// copy of mermaid (no network dependency at render time), render a flowchart,
// then screenshot the SVG to a PNG.
//
// Run with:  NODE_PATH="/Users/broodierchip-m1air/node_modules" node demo/render_diagram.js
//
// Fails LOUDLY (non-zero exit) on any mermaid parse/render error so a broken
// diagram never masquerades as a successful screenshot.

const { chromium } = require('playwright');
const path = require('path');
const fs = require('fs');

const REPO = '/Users/broodierchip-m1air/Desktop/omni-guard';
const OUT = path.join(REPO, 'architecture.png');
const MERMAID_JS = path.join(REPO, 'demo', 'mermaid.min.js');

// ── AS-BUILT flow. Special chars in labels (/, (), :) are quoted. ────────────
const GRAPH = String.raw`
flowchart TB
  %% ============== ON-CHAIN SOURCES ==============
  subgraph CHAIN["On-chain data"]
    direction LR
    SRC["Ethereum mainnet<br/>tx · events"]
    ESCAN["Etherscan API"]
    RPC["JSON-RPC node"]
    SRC --> ESCAN
    SRC --> RPC
  end

  %% ============== INGESTION ==============
  subgraph INGEST["Ingestion  (Python → Splunk HEC)"]
    direction LR
    ING1["historical_scan.py"]
    ING2["ingest_transactions.py"]
    SCOPE["scope.json<br/>(Immunefi scope)"]
  end

  %% ============== SPLUNK — THE BRAIN ==============
  subgraph SPLUNK["Splunk Enterprise  —  the brain"]
    direction TB
    ST["Typed sourcetypes (index: omni_guard_security)<br/>layerzero:transaction · :event · :source<br/>:audit_finding · :scope"]
    DET["SPL detections  (~14 saved searches)<br/>eventstats z-score · streamstats · predict<br/>cluster · transaction · MLTK DBSCAN"]
    KVB[("kvstore<br/>contract_baselines")]
    ALERT["layerzero:alert<br/>(written via | collect)"]

    subgraph AGENTBOX["In-app AI Agent  —  argus_agent.py  (modular input, every 5 min)"]
      direction TB
      AG["Deterministic Splunk-native tier-0 triage<br/>reasoning_engine = splunk_native_tier0<br/>verdict = SPL severity · confidence = f(severity)<br/>poc_worthwhile if HIGH / CRITICAL"]
      KVS[("kvstore<br/>argus_agent_state<br/>(KV dedup)")]
    end

    REPORT["layerzero:ai_report"]
    TRIG["layerzero:poc_trigger"]

    ST --> DET
    DET <--> KVB
    DET --> ALERT
    ALERT --> AG
    AG <--> KVS
    AG --> REPORT
    AG --> TRIG
  end

  %% ============== EXTERNAL FORK VALIDATION ==============
  subgraph FORK["External fork validation  (real, off-Splunk)"]
    direction TB
    VAL["poc/validate_finding.py"]
    ANVIL["Anvil — fork Ethereum mainnet @ block N-1"]
    FORGE["Foundry — forge exploit test (.t.sol)"]
    FRES["layerzero:fork_result<br/>HONEST verdict:<br/>CONFIRMED only if test assertions pass<br/>else REJECTED · gain is null, never faked"]
    VAL --> ANVIL --> FORGE --> FRES
  end

  SUBMIT["Drafted Immunefi submission<br/>(human-reviewed before filing)"]

  %% ============== ROADMAP / NOT IN LIVE LOOP ==============
  subgraph ROADMAP["Roadmap  —  NOT in the live loop"]
    direction TB
    LLM["agent/splunk_ai.py<br/>local MLX Foundation-Sec LLM<br/>(deeper tier-1 reasoning)"]
    MCP["agent/mcp_agent.py<br/>MCP-over-SSE orchestrator<br/>DEPRECATED / unused"]
    SAIA["SAIA cloud LLM tenant<br/>never activated"]
  end

  %% ============== PRIMARY DATA FLOW ==============
  ESCAN --> ING1
  RPC --> ING2
  ING1 --> ST
  ING2 --> ST
  SCOPE --> ST
  FRES --> REPORT

  TRIG -->|"poc_worthwhile findings"| VAL
  FRES --> SUBMIT

  %% ============== ROADMAP DASHED LINKS ==============
  AG -.->|"roadmap: deeper triage"| LLM
  AG -.->|"deprecated path"| MCP
  LLM -.->|"future cloud tier"| SAIA

  %% ============== STYLING (Splunk-ish) ==============
  classDef chain fill:#0b3d2e,stroke:#1d8a5e,color:#eafff5,stroke-width:1px;
  classDef ingest fill:#163a5f,stroke:#2f7fd1,color:#eaf3ff,stroke-width:1px;
  classDef splunkbox fill:#0f3460,stroke:#5b9dff,color:#eaf0ff,stroke-width:1px;
  classDef detect fill:#1a4a7a,stroke:#5b9dff,color:#eaf0ff,stroke-width:1px;
  classDef alertnode fill:#7a4a16,stroke:#f6a623,color:#fff4e0,stroke-width:1.5px;
  classDef agentnode fill:#533483,stroke:#9b8cff,color:#f3eeff,stroke-width:1.5px;
  classDef outnode fill:#1f6b4a,stroke:#34c98a,color:#eafff5,stroke-width:1.5px;
  classDef forknode fill:#5a2a3a,stroke:#e0608a,color:#ffeaf2,stroke-width:1px;
  classDef kv fill:#102a44,stroke:#5b9dff,color:#cfe0ff,stroke-width:1px;
  classDef submit fill:#1d7a3a,stroke:#43d66e,color:#eafff0,stroke-width:2px;
  classDef roadmap fill:#2a2f3a,stroke:#6b7488,color:#aab4c8,stroke-width:1px,stroke-dasharray:6 4;

  class SRC,ESCAN,RPC chain;
  class ING1,ING2,SCOPE ingest;
  class ST,DET detect;
  class KVB,KVS kv;
  class ALERT alertnode;
  class AG agentnode;
  class REPORT,TRIG outnode;
  class VAL,ANVIL,FORGE,FRES forknode;
  class SUBMIT submit;
  class LLM,MCP,SAIA roadmap;

  style CHAIN fill:#08251b,stroke:#1d8a5e,color:#9affcf;
  style INGEST fill:#0c2540,stroke:#2f7fd1,color:#bcd9ff;
  style SPLUNK fill:#091e38,stroke:#5b9dff,color:#cfe0ff;
  style AGENTBOX fill:#2c1c4a,stroke:#9b8cff,color:#d7ccff;
  style FORK fill:#3a1a26,stroke:#e0608a,color:#ffc4d8;
  style ROADMAP fill:#1a1d24,stroke:#5a6172,color:#8a93a8;
`;

const HTML = `<!doctype html><html><head><meta charset="utf-8">
<style>
  html,body{margin:0;padding:0;background:#05070f;}
  #wrap{padding:36px 44px;display:inline-block;background:#05070f;}
  .title{font-family:-apple-system,Helvetica,Arial,sans-serif;color:#eaf0ff;
    font-size:30px;font-weight:800;letter-spacing:.02em;margin:0 0 4px 4px;}
  .sub{font-family:-apple-system,Helvetica,Arial,sans-serif;color:#7f8cab;
    font-size:15px;margin:0 0 22px 4px;font-weight:500;}
  .mermaid{font-family:-apple-system,'Helvetica Neue',Helvetica,Arial,sans-serif;}
  .mermaid svg{max-width:none !important;}
</style></head>
<body>
  <div id="wrap">
    <p class="title">ARGUS — As-built architecture</p>
    <p class="sub">App ↔ Splunk interaction · in-app AI agent · on-chain → detection → fork-validated submission. Dashed = roadmap, not in the live loop.</p>
    <div class="mermaid" id="dia">${GRAPH}</div>
  </div>
</body></html>`;

(async () => {
  const errors = [];
  const browser = await chromium.launch({ headless: true });
  const ctx = await browser.newContext({
    viewport: { width: 2000, height: 1400 },
    deviceScaleFactor: 2,
  });
  const page = await ctx.newPage();

  page.on('pageerror', (e) => { errors.push('pageerror: ' + e.message); });
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push('console.error: ' + m.text());
  });

  await page.setContent(HTML, { waitUntil: 'domcontentloaded' });

  // Inject the LOCAL mermaid bundle — no network needed at render time.
  await page.addScriptTag({ path: MERMAID_JS });

  // Render explicitly; capture any thrown parse/render error.
  const renderError = await page.evaluate(async () => {
    try {
      // The local UMD build exposes mermaid on window.
      // eslint-disable-next-line no-undef
      mermaid.initialize({
        startOnLoad: false,
        theme: 'dark',
        securityLevel: 'loose',
        flowchart: { htmlLabels: true, curve: 'basis', nodeSpacing: 45, rankSpacing: 60 },
        themeVariables: {
          fontSize: '15px',
          fontFamily: '-apple-system, Helvetica, Arial, sans-serif',
          lineColor: '#5b9dff',
        },
      });
      // eslint-disable-next-line no-undef
      await mermaid.run({ querySelector: '.mermaid' });
      return null;
    } catch (e) {
      return String(e && e.message ? e.message : e);
    }
  });

  if (renderError) errors.push('mermaid.run threw: ' + renderError);

  // A real render produces an <svg> containing .node elements; a parse error
  // produces an error <svg> with class "error-icon". Require a real node.
  let ok = false;
  try {
    await page.waitForSelector('.mermaid svg .node', { timeout: 15000 });
    const hasError = await page.$('.mermaid svg .error-icon');
    ok = !hasError;
  } catch (e) {
    errors.push('waitForSelector(.node) failed: ' + e.message);
  }

  if (!ok) {
    console.error('RENDER FAILED — diagram did not produce a valid SVG.');
    for (const e of errors) console.error('  - ' + e);
    await browser.close();
    process.exit(1);
  }

  // Screenshot just the wrapper so we capture title + full diagram tightly.
  const el = await page.$('#wrap');
  await el.screenshot({ path: OUT });
  await browser.close();

  const sz = fs.statSync(OUT).size;
  console.log('OK — wrote ' + OUT + ' (' + Math.round(sz / 1024) + ' KB)');
  if (errors.length) {
    console.log('Non-fatal warnings during render:');
    for (const e of errors) console.log('  - ' + e);
  }
})().catch((e) => {
  console.error('FATAL: ' + (e && e.stack ? e.stack : e));
  process.exit(1);
});
