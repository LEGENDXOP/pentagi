package tools

// browserServerScript is the Node.js Playwright server script that runs inside the container.
// It is written to a file in the container on first use.
const browserServerScript = `#!/usr/bin/env node
/**
 * PentAGI Playwright Browser Server
 * HTTP server wrapping Playwright with stealth plugin for headless browser automation.
 */

const http = require('http');
const { chromium } = require('playwright-extra');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');
const path = require('path');
const fs = require('fs');

chromium.use(StealthPlugin());

const PORT = parseInt(process.env.BROWSER_PORT || '9222', 10);
const SCREENSHOT_DIR = '/work/evidence/screenshots';
const DEFAULT_TIMEOUT = parseInt(process.env.BROWSER_TIMEOUT || '30', 10) * 1000;
const MAX_CONSOLE_LOGS = 500;
const MAX_RESPONSE_BODY = 64 * 1024;

let browserInstance = null;
let pageInstance = null;
let consoleLogs = [];
let startingUp = false;

function ensureScreenshotDir() {
  try { fs.mkdirSync(SCREENSHOT_DIR, { recursive: true }); } catch (e) {}
}

async function ensureBrowser() {
  if (browserInstance && browserInstance.isConnected()) {
    if (pageInstance && !pageInstance.isClosed()) return pageInstance;
    pageInstance = await browserInstance.newPage();
    setupPageListeners(pageInstance);
    return pageInstance;
  }
  if (startingUp) {
    for (let i = 0; i < 30; i++) {
      await new Promise(r => setTimeout(r, 1000));
      if (browserInstance && browserInstance.isConnected() && pageInstance && !pageInstance.isClosed()) return pageInstance;
    }
    throw new Error('Browser startup timed out');
  }
  startingUp = true;
  try {
    browserInstance = await chromium.launch({
      headless: true,
      args: [
        '--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage',
        '--disable-accelerated-2d-canvas', '--no-first-run', '--no-zygote',
        '--single-process', '--disable-gpu', '--disable-background-networking',
        '--disable-default-apps', '--disable-extensions', '--disable-sync',
        '--disable-translate', '--disable-blink-features=AutomationControlled',
        '--ignore-certificate-errors',
      ],
    });
    browserInstance.on('disconnected', () => { browserInstance = null; pageInstance = null; });
    pageInstance = await browserInstance.newPage();
    await pageInstance.setViewportSize({ width: 1920, height: 1080 });
    setupPageListeners(pageInstance);
    return pageInstance;
  } finally { startingUp = false; }
}

function setupPageListeners(page) {
  consoleLogs = [];
  page.on('console', (msg) => {
    if (consoleLogs.length < MAX_CONSOLE_LOGS) consoleLogs.push({ type: msg.type(), text: msg.text(), timestamp: new Date().toISOString() });
  });
  page.on('pageerror', (err) => {
    if (consoleLogs.length < MAX_CONSOLE_LOGS) consoleLogs.push({ type: 'error', text: err.message || String(err), timestamp: new Date().toISOString() });
  });
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', (chunk) => { body += chunk; if (body.length > 1048576) reject(new Error('Body too large')); });
    req.on('end', () => { try { resolve(body ? JSON.parse(body) : {}); } catch (e) { reject(new Error('Invalid JSON')); } });
    req.on('error', reject);
  });
}

function sendJSON(res, code, data) {
  const b = JSON.stringify(data);
  res.writeHead(code, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(b) });
  res.end(b);
}

function truncate(s, n) { return (!s || s.length <= n) ? s : s.substring(0, n) + '\n... [truncated]'; }

async function handleNavigate(body) {
  if (!body.url) throw new Error('url is required');
  const page = await ensureBrowser();
  const response = await page.goto(body.url, { waitUntil: body.waitUntil || 'domcontentloaded', timeout: body.timeout || DEFAULT_TIMEOUT });
  const title = await page.title();
  const status = response ? response.status() : null;
  const headers = response ? response.headers() : {};
  let content = '';
  try { content = await page.evaluate(() => document.body ? document.body.innerText : ''); content = truncate(content, MAX_RESPONSE_BODY); } catch (e) { content = '[error: ' + e.message + ']'; }
  return { success: true, url: page.url(), title, status, content, headers: { 'content-type': headers['content-type'] || '', 'server': headers['server'] || '', 'x-powered-by': headers['x-powered-by'] || '' } };
}

async function handleClick(body) {
  if (!body.selector) throw new Error('selector is required');
  const page = await ensureBrowser();
  await page.click(body.selector, { timeout: body.timeout || DEFAULT_TIMEOUT });
  try { await page.waitForLoadState('domcontentloaded', { timeout: 5000 }); } catch (e) {}
  return { success: true, url: page.url(), title: await page.title(), message: 'Clicked: ' + body.selector };
}

async function handleFill(body) {
  if (!body.selector) throw new Error('selector is required');
  if (body.value === undefined) throw new Error('value is required');
  const page = await ensureBrowser();
  await page.fill(body.selector, String(body.value), { timeout: body.timeout || DEFAULT_TIMEOUT });
  return { success: true, message: 'Filled "' + body.selector + '" with ' + String(body.value).length + ' chars' };
}

async function handleScreenshot(body) {
  ensureScreenshotDir();
  const page = await ensureBrowser();
  const ts = new Date().toISOString().replace(/[:.]/g, '-');
  const filename = 'playwright-' + ts + '.png';
  const filepath = path.join(SCREENSHOT_DIR, filename);
  await page.screenshot({ path: filepath, fullPage: body.fullPage !== false, type: 'png' });
  const stats = fs.statSync(filepath);
  return { success: true, path: filepath, filename, size: stats.size, url: page.url(), title: await page.title() };
}

async function handleEvaluate(body) {
  if (!body.expression) throw new Error('expression is required');
  const page = await ensureBrowser();
  const result = await page.evaluate(body.expression);
  let serialized;
  try { serialized = JSON.stringify(result, null, 2); serialized = truncate(serialized, MAX_RESPONSE_BODY); } catch (e) { serialized = String(result); }
  return { success: true, result: serialized, type: typeof result };
}

async function handleCookies() {
  const page = await ensureBrowser();
  const cookies = await page.context().cookies();
  return { success: true, url: page.url(), count: cookies.length, cookies: cookies.map(c => ({ name: c.name, value: truncate(c.value, 512), domain: c.domain, path: c.path, secure: c.secure, httpOnly: c.httpOnly, sameSite: c.sameSite, expires: c.expires })) };
}

async function handleConsole() { return { success: true, count: consoleLogs.length, logs: consoleLogs.slice(-100) }; }

async function handleClose() {
  if (pageInstance && !pageInstance.isClosed()) await pageInstance.close().catch(() => {});
  pageInstance = null;
  if (browserInstance) await browserInstance.close().catch(() => {});
  browserInstance = null;
  consoleLogs = [];
  return { success: true, message: 'Browser closed' };
}

const server = http.createServer(async (req, res) => {
  const url = req.url.split('?')[0];
  const method = req.method.toUpperCase();
  try {
    if (method === 'GET' && url === '/health') return sendJSON(res, 200, { success: true, browser: browserInstance ? 'connected' : 'not started', uptime: process.uptime() });
    if (method === 'GET' && url === '/cookies') return sendJSON(res, 200, await handleCookies());
    if (method === 'GET' && url === '/console') return sendJSON(res, 200, await handleConsole());
    if (method !== 'POST') return sendJSON(res, 405, { success: false, error: 'Method not allowed' });
    const body = await parseBody(req);
    let result;
    switch (url) {
      case '/navigate': result = await handleNavigate(body); break;
      case '/click': result = await handleClick(body); break;
      case '/fill': result = await handleFill(body); break;
      case '/screenshot': result = await handleScreenshot(body); break;
      case '/evaluate': result = await handleEvaluate(body); break;
      case '/close': result = await handleClose(); break;
      default: return sendJSON(res, 404, { success: false, error: 'Unknown endpoint' });
    }
    sendJSON(res, 200, result);
  } catch (err) {
    if (err.message && (err.message.includes('Target closed') || err.message.includes('Browser closed'))) { browserInstance = null; pageInstance = null; consoleLogs = []; }
    sendJSON(res, 500, { success: false, error: err.message || 'Internal error' });
  }
});

server.listen(PORT, '127.0.0.1', () => { console.log('[browser-server] listening on port ' + PORT); });
process.on('SIGTERM', async () => { await handleClose(); server.close(); process.exit(0); });
process.on('uncaughtException', (err) => { console.error('[browser-server] uncaught:', err.message); });
process.on('unhandledRejection', (r) => { console.error('[browser-server] rejection:', r); });
`
