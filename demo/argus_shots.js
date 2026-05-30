// Argus demo capture — logs into Splunk web, opens the Argus dashboard,
// waits for panels to render, and screenshots them for the demo video.
const { chromium } = require('playwright');
const fs = require('fs');

const BASE = 'http://localhost:8000';
const USER = process.env.SPLUNK_USER;
const PASS = process.env.SPLUNK_PASS;
const OUT = '/Users/broodierchip-m1air/Desktop/omni-guard/demo/shots';
const DASH = `${BASE}/en-US/app/omni_guard/omni_guard?form.time_range.earliest=-120d&form.time_range.latest=now&form.chain_filter=*`;

(async () => {
  fs.mkdirSync(OUT, { recursive: true });
  const browser = await chromium.launch({ headless: true });
  const ctx = await browser.newContext({ viewport: { width: 1920, height: 1080 }, deviceScaleFactor: 2 });
  const page = await ctx.newPage();

  // ---- login ----
  await page.goto(`${BASE}/en-US/account/login`, { waitUntil: 'domcontentloaded', timeout: 60000 });
  await page.waitForTimeout(2000);
  // Splunk login inputs — try common selectors
  const userSel = ['input[name="username"]', '#username', 'input[data-test="username"]'];
  const passSel = ['input[name="password"]', '#password', 'input[data-test="password"]'];
  async function fillFirst(selectors, val) {
    for (const s of selectors) {
      const el = await page.$(s);
      if (el) { await el.fill(val); return true; }
    }
    return false;
  }
  const okU = await fillFirst(userSel, USER);
  const okP = await fillFirst(passSel, PASS);
  console.log('login fields filled:', okU, okP);
  await page.keyboard.press('Enter');
  await page.waitForTimeout(6000);
  console.log('after login url:', page.url());

  // ---- dashboard ----
  await page.goto(DASH, { waitUntil: 'domcontentloaded', timeout: 90000 });
  console.log('dashboard loading, waiting for panels to run searches...');
  await page.waitForTimeout(38000); // let Splunk run all panel searches
  // dismiss any "new dashboards" / tour popovers if present
  try { await page.keyboard.press('Escape'); } catch (e) {}
  await page.waitForTimeout(1500);

  // full page
  await page.screenshot({ path: `${OUT}/01_dashboard_full.png`, fullPage: true });
  console.log('saved full dashboard');

  // top viewport (KPIs + investigation log header)
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.waitForTimeout(800);
  await page.screenshot({ path: `${OUT}/02_kpis.png` });

  // scroll through to capture each row as a viewport "slide"
  const total = await page.evaluate(() => document.body.scrollHeight);
  let i = 3;
  for (let y = 700; y < total; y += 850) {
    await page.evaluate((yy) => window.scrollTo(0, yy), y);
    await page.waitForTimeout(900);
    await page.screenshot({ path: `${OUT}/${String(i).padStart(2,'0')}_row.png` });
    i++;
  }
  console.log('saved', i - 1, 'screenshots total');

  await browser.close();
})().catch(e => { console.error('CAPTURE ERROR:', e.message); process.exit(1); });
