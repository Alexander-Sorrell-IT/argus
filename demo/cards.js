// Render title + end cards to 1920x1080 PNGs via headless Chromium.
const { chromium } = require('playwright');
const OUT = '/Users/broodierchip-m1air/Desktop/omni-guard/demo/shots';

const base = (inner) => `<!doctype html><html><head><meta charset=utf8>
<style>
  html,body{margin:0;width:1920px;height:1080px;font-family:-apple-system,Helvetica,Arial,sans-serif;
    background:radial-gradient(1200px 700px at 50% 35%, #14213a 0%, #0a0f1f 60%, #05070f 100%);color:#eaf0ff;
    display:flex;align-items:center;justify-content:center;text-align:center;}
  .wrap{max-width:1500px}
  .eye{font-size:120px;letter-spacing:.18em;font-weight:800;background:linear-gradient(90deg,#5b9dff,#9b8cff);
    -webkit-background-clip:text;background-clip:text;color:transparent;margin:0}
  .sub{font-size:40px;color:#aab8d8;margin:18px 0 0;font-weight:500}
  .tag{font-size:26px;color:#6b7aa0;margin-top:46px;letter-spacing:.04em}
  ul{list-style:none;padding:0;margin:40px 0 0;font-size:34px;line-height:1.9;color:#cdd8f0;text-align:left;display:inline-block}
  li:before{content:"✓ ";color:#5b9dff;font-weight:800}
  .small{font-size:24px;color:#6b7aa0;margin-top:40px}
</style></head><body><div class=wrap>${inner}</div></body></html>`;

const TITLE = base(`
  <p class=eye>ARGUS</p>
  <p class=sub>A Splunk-native security operations center for cross-chain DeFi</p>
  <p class=tag>Splunk Agentic Ops Hackathon 2026 · Security track · demo protocol: LayerZero</p>`);

const END = base(`
  <p class=eye style="font-size:90px">ARGUS</p>
  <ul>
    <li>Splunk-native: SPL detections, KV-store state, in-app AI agent</li>
    <li>AI-written detections: Splunk's hosted AI Assistant authors the SPL &mdash; no third-party model</li>
    <li>Ground-truth: fork-validated, honest verdicts &mdash; no crying wolf</li>
  </ul>
  <p class=small>Open source (AGPL-3.0) · protocol-agnostic via one YAML</p>`);

(async () => {
  const b = await chromium.launch({ headless: true });
  const p = await (await b.newContext({ viewport:{width:1920,height:1080}, deviceScaleFactor:1 })).newPage();
  await p.setContent(TITLE, { waitUntil:'networkidle' }); await p.waitForTimeout(300);
  await p.screenshot({ path:`${OUT}/00_title.png` });
  await p.setContent(END, { waitUntil:'networkidle' }); await p.waitForTimeout(300);
  await p.screenshot({ path:`${OUT}/99_end.png` });
  await b.close(); console.log('cards rendered');
})().catch(e=>{console.error(e.message);process.exit(1)});
