// Records demo/trailer/trailer.html to a webm via Playwright's native video recording.
const { chromium } = require('playwright');
const path = require('path');

const DIR = '/Users/broodierchip-m1air/Desktop/omni-guard/demo/trailer';
const OUTDIR = path.join(DIR, 'raw');
const HTML = 'file://' + path.join(DIR, 'trailer.html');
const W = 1920, H = 1080;
const PLAY_MS = 37500; // a touch past the 37.4s timeline end

(async () => {
  const browser = await chromium.launch({
    headless: true,
    args: ['--force-color-profile=srgb', '--hide-scrollbars', '--disable-gpu-vsync']
  });
  const ctx = await browser.newContext({
    viewport: { width: W, height: H },
    deviceScaleFactor: 1,
    recordVideo: { dir: OUTDIR, size: { width: W, height: H } }
  });
  const page = await ctx.newPage();

  await page.goto(HTML, { waitUntil: 'load', timeout: 60000 });
  // wait for script init
  await page.waitForFunction('window.__ready === true', { timeout: 15000 });
  // small settle so first recorded frames are the styled stage, not white
  await page.waitForTimeout(600);

  // build + start timeline
  await page.evaluate(() => { window.__tl = window.buildTimeline(); });
  console.log('timeline started, playing for', PLAY_MS, 'ms');

  await page.waitForTimeout(PLAY_MS);

  const video = page.video();
  await ctx.close(); // flushes/saves the webm
  await browser.close();

  const file = await video.path();
  console.log('VIDEO_PATH=' + file);
})().catch(e => { console.error(e); process.exit(1); });
