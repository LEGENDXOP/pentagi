#!/usr/bin/env node
/**
 * PentAGI Playwright Browser Server
 *
 * HTTP server wrapping Playwright with stealth plugin for headless browser
 * automation inside Kali containers. Supports navigation, clicking, form filling,
 * screenshots, JS evaluation, cookie extraction, and console log capture.
 *
 * Endpoints:
 *   POST /navigate    { url, waitUntil?, timeout? }
 *   POST /click       { selector, timeout? }
 *   POST /fill        { selector, value, timeout? }
 *   POST /screenshot  { path?, fullPage? }
 *   POST /evaluate    { expression }
 *   GET  /cookies
 *   GET  /console
 *   GET  /health
 *   POST /close
 *
 * Usage: BROWSER_PORT=9222 node browser-server.js
 */

const http = require('http');
const { chromium } = require('playwright-extra');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');
const path = require('path');
const fs = require('fs');

// Apply stealth plugin to evade bot detection
chromium.use(StealthPlugin());

const PORT = parseInt(process.env.BROWSER_PORT || '9222', 10);
const SCREENSHOT_DIR = '/work/evidence/screenshots';
const DEFAULT_TIMEOUT = parseInt(process.env.BROWSER_TIMEOUT || '30', 10) * 1000;
const MAX_CONSOLE_LOGS = 500;
const MAX_RESPONSE_BODY = 64 * 1024; // 64KB max for page content in responses

let browserInstance = null;
let pageInstance = null;
let consoleLogs = [];
let startingUp = false;

// Ensure screenshot directory exists
function ensureScreenshotDir() {
  try {
    fs.mkdirSync(SCREENSHOT_DIR, { recursive: true });
  } catch (e) {
    // ignore if already exists
  }
}

async function ensureBrowser() {
  if (browserInstance && browserInstance.isConnected()) {
    if (pageInstance && !pageInstance.isClosed()) {
      return pageInstance;
    }
    // Page was closed, create a new one
    pageInstance = await browserInstance.newPage();
    setupPageListeners(pageInstance);
    return pageInstance;
  }

  // Prevent concurrent startup
  if (startingUp) {
    // Wait for existing startup
    for (let i = 0; i < 30; i++) {
      await new Promise(r => setTimeout(r, 1000));
      if (browserInstance && browserInstance.isConnected()) {
        if (pageInstance && !pageInstance.isClosed()) {
          return pageInstance;
        }
      }
    }
    throw new Error('Browser startup timed out');
  }

  startingUp = true;
  try {
    browserInstance = await chromium.launch({
      headless: true,
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-accelerated-2d-canvas',
        '--no-first-run',
        '--no-zygote',
        '--single-process',
        '--disable-gpu',
        '--disable-background-networking',
        '--disable-default-apps',
        '--disable-extensions',
        '--disable-sync',
        '--disable-translate',
        '--disable-blink-features=AutomationControlled',
        '--ignore-certificate-errors',
      ],
    });

    // Handle browser disconnect
    browserInstance.on('disconnected', () => {
      console.log('[browser-server] Browser disconnected, will restart on next request');
      browserInstance = null;
      pageInstance = null;
    });

    pageInstance = await browserInstance.newPage();

    // Set realistic viewport and user agent
    await pageInstance.setViewportSize({ width: 1920, height: 1080 });

    setupPageListeners(pageInstance);

    console.log('[browser-server] Browser launched successfully');
    return pageInstance;
  } finally {
    startingUp = false;
  }
}

function setupPageListeners(page) {
  consoleLogs = [];

  page.on('console', (msg) => {
    if (consoleLogs.length < MAX_CONSOLE_LOGS) {
      consoleLogs.push({
        type: msg.type(),
        text: msg.text(),
        timestamp: new Date().toISOString(),
      });
    }
  });

  page.on('pageerror', (err) => {
    if (consoleLogs.length < MAX_CONSOLE_LOGS) {
      consoleLogs.push({
        type: 'error',
        text: err.message || String(err),
        timestamp: new Date().toISOString(),
      });
    }
  });
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', (chunk) => {
      body += chunk;
      if (body.length > 1024 * 1024) {
        reject(new Error('Request body too large'));
      }
    });
    req.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (e) {
        reject(new Error('Invalid JSON: ' + e.message));
      }
    });
    req.on('error', reject);
  });
}

function sendJSON(res, statusCode, data) {
  const body = JSON.stringify(data);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(body),
  });
  res.end(body);
}

function truncate(str, maxLen) {
  if (!str || str.length <= maxLen) return str;
  return str.substring(0, maxLen) + '\n... [truncated at ' + maxLen + ' bytes]';
}

// Request handlers
async function handleNavigate(body) {
  const { url, waitUntil, timeout } = body;
  if (!url) throw new Error('url is required');

  const page = await ensureBrowser();
  const response = await page.goto(url, {
    waitUntil: waitUntil || 'domcontentloaded',
    timeout: timeout || DEFAULT_TIMEOUT,
  });

  const title = await page.title();
  const currentUrl = page.url();
  const status = response ? response.status() : null;
  const headers = response ? response.headers() : {};

  // Get page text content (truncated)
  let content = '';
  try {
    content = await page.evaluate(() => document.body ? document.body.innerText : '');
    content = truncate(content, MAX_RESPONSE_BODY);
  } catch (e) {
    content = '[could not extract page content: ' + e.message + ']';
  }

  return {
    success: true,
    url: currentUrl,
    title,
    status,
    contentLength: content.length,
    content,
    headers: {
      'content-type': headers['content-type'] || '',
      'server': headers['server'] || '',
      'x-powered-by': headers['x-powered-by'] || '',
    },
  };
}

async function handleClick(body) {
  const { selector, timeout } = body;
  if (!selector) throw new Error('selector is required');

  const page = await ensureBrowser();
  await page.click(selector, { timeout: timeout || DEFAULT_TIMEOUT });

  // Wait for possible navigation/load
  try {
    await page.waitForLoadState('domcontentloaded', { timeout: 5000 });
  } catch (e) {
    // Ignore timeout — click might not trigger navigation
  }

  const title = await page.title();
  const currentUrl = page.url();

  return {
    success: true,
    url: currentUrl,
    title,
    message: `Clicked element matching "${selector}"`,
  };
}

async function handleFill(body) {
  const { selector, value, timeout } = body;
  if (!selector) throw new Error('selector is required');
  if (value === undefined || value === null) throw new Error('value is required');

  const page = await ensureBrowser();
  await page.fill(selector, String(value), { timeout: timeout || DEFAULT_TIMEOUT });

  return {
    success: true,
    message: `Filled "${selector}" with value (${String(value).length} chars)`,
  };
}

async function handleScreenshot(body) {
  const { fullPage } = body;

  ensureScreenshotDir();

  const page = await ensureBrowser();
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const filename = `playwright-${timestamp}.png`;
  const filepath = path.join(SCREENSHOT_DIR, filename);

  await page.screenshot({
    path: filepath,
    fullPage: fullPage !== false, // default true
    type: 'png',
  });

  const stats = fs.statSync(filepath);

  return {
    success: true,
    path: filepath,
    filename,
    size: stats.size,
    url: page.url(),
    title: await page.title(),
  };
}

async function handleEvaluate(body) {
  const { expression } = body;
  if (!expression) throw new Error('expression is required');

  const page = await ensureBrowser();
  const result = await page.evaluate(expression);

  let serialized;
  try {
    serialized = JSON.stringify(result, null, 2);
    serialized = truncate(serialized, MAX_RESPONSE_BODY);
  } catch (e) {
    serialized = String(result);
  }

  return {
    success: true,
    result: serialized,
    type: typeof result,
  };
}

async function handleCookies() {
  const page = await ensureBrowser();
  const cookies = await page.context().cookies();

  return {
    success: true,
    url: page.url(),
    count: cookies.length,
    cookies: cookies.map((c) => ({
      name: c.name,
      value: truncate(c.value, 512),
      domain: c.domain,
      path: c.path,
      secure: c.secure,
      httpOnly: c.httpOnly,
      sameSite: c.sameSite,
      expires: c.expires,
    })),
  };
}

async function handleConsole() {
  return {
    success: true,
    count: consoleLogs.length,
    logs: consoleLogs.slice(-100), // Last 100 entries
  };
}

async function handleClose() {
  if (pageInstance && !pageInstance.isClosed()) {
    await pageInstance.close().catch(() => {});
    pageInstance = null;
  }
  if (browserInstance) {
    await browserInstance.close().catch(() => {});
    browserInstance = null;
  }
  consoleLogs = [];
  return { success: true, message: 'Browser closed' };
}

function handleHealth() {
  return {
    success: true,
    browser: browserInstance ? (browserInstance.isConnected() ? 'connected' : 'disconnected') : 'not started',
    page: pageInstance ? (pageInstance.isClosed() ? 'closed' : 'active') : 'none',
    consoleLogs: consoleLogs.length,
    uptime: process.uptime(),
  };
}

// HTTP server
const server = http.createServer(async (req, res) => {
  const url = req.url.split('?')[0];
  const method = req.method.toUpperCase();

  try {
    let result;

    if (method === 'GET' && url === '/health') {
      result = handleHealth();
      return sendJSON(res, 200, result);
    }

    if (method === 'GET' && url === '/cookies') {
      result = await handleCookies();
      return sendJSON(res, 200, result);
    }

    if (method === 'GET' && url === '/console') {
      result = await handleConsole();
      return sendJSON(res, 200, result);
    }

    if (method !== 'POST') {
      return sendJSON(res, 405, { success: false, error: 'Method not allowed' });
    }

    const body = await parseBody(req);

    switch (url) {
      case '/navigate':
        result = await handleNavigate(body);
        break;
      case '/click':
        result = await handleClick(body);
        break;
      case '/fill':
        result = await handleFill(body);
        break;
      case '/screenshot':
        result = await handleScreenshot(body);
        break;
      case '/evaluate':
        result = await handleEvaluate(body);
        break;
      case '/close':
        result = await handleClose();
        break;
      default:
        return sendJSON(res, 404, { success: false, error: 'Unknown endpoint: ' + url });
    }

    sendJSON(res, 200, result);
  } catch (err) {
    console.error(`[browser-server] Error on ${method} ${url}:`, err.message);

    // If it's a browser crash, reset state
    if (err.message && (err.message.includes('Target closed') || err.message.includes('Browser closed'))) {
      browserInstance = null;
      pageInstance = null;
      consoleLogs = [];
    }

    sendJSON(res, 500, {
      success: false,
      error: err.message || 'Internal server error',
    });
  }
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`[browser-server] Playwright server listening on http://127.0.0.1:${PORT}`);
  console.log(`[browser-server] Screenshot directory: ${SCREENSHOT_DIR}`);
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('[browser-server] Shutting down...');
  await handleClose();
  server.close();
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('[browser-server] Interrupted, shutting down...');
  await handleClose();
  server.close();
  process.exit(0);
});

process.on('uncaughtException', (err) => {
  console.error('[browser-server] Uncaught exception:', err.message);
  // Don't exit — try to keep serving
});

process.on('unhandledRejection', (reason) => {
  console.error('[browser-server] Unhandled rejection:', reason);
});
