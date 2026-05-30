// Fast verification: seek the GSAP timeline to key timestamps and screenshot full-res.
const { chromium } = require('playwright');
const path = require('path');
const DIR = '/Users/broodierchip-m1air/Desktop/omni-guard/demo/trailer';
const HTML = 'file://' + path.join(DIR, 'trailer.html');
const SEEKS = [3.2, 11.5, 19.6, 22.0, 26.2, 33.6];

(async () => {
  const browser = await chromium.launch({ headless: true });
  const ctx = await browser.newContext({ viewport: { width: 1920, height: 1080 }, deviceScaleFactor: 1 });
  const page = await ctx.newPage();
  await page.goto(HTML, { waitUntil: 'load' });
  await page.waitForFunction('window.__ready === true');
  await page.evaluate(() => { window.__tl = window.buildTimeline(); window.__tl.pause(); });
  for (const t of SEEKS) {
    await page.evaluate((tt) => { window.__tl.seek(tt, false); }, t);
    await page.waitForTimeout(250);
    const f = path.join(DIR, `vf_${String(t).replace('.','_')}.png`);
    await page.screenshot({ path: f });
    console.log('shot', f);
  }
  await browser.close();
})().catch(e => { console.error(e); process.exit(1); });
