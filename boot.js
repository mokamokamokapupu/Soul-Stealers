'use strict';

// Render's free plan has no persistent disk: every deploy starts from a fresh
// checkout. While a new instance starts, the old one is still serving, so the
// new one asks it for everything in data/ before loading any of it.

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');

const SYNC_PATH = '/api/sync';
const SYNC_HEADER = 'x-sync';
const MAX_FILE_BYTES = 8 * 1024 * 1024;
const MAX_TOTAL_BYTES = 400 * 1024 * 1024;
const DATA_DIR = path.join(__dirname, 'data');
const INCOMING_DIR = path.join(__dirname, 'data.incoming');
const REL_PATH_RE = /^[A-Za-z0-9._-]+(\/[A-Za-z0-9._-]+)*$/;

const SYNC_KEY = (() => {
  const parts = [process.env.SPOTIFY_CLIENT_SECRET || '', process.env.SOUL_STUDIES_PREFS_SECRET || ''];
  if (!parts.some((p) => p.length >= 16)) return null;
  return crypto.createHash('sha256').update('sync|' + parts.join('|')).digest();
})();

function sign(stamp, nonce) {
  return crypto.createHmac('sha256', SYNC_KEY).update(stamp + '.' + nonce).digest('hex');
}

const usedNonces = new Map();

function accepts(req) {
  if (!SYNC_KEY || req.method !== 'POST') return false;
  const m = /^(\d{13})\.([0-9a-f]{32})\.([0-9a-f]{64})$/.exec(String(req.headers[SYNC_HEADER] || ''));
  if (!m) return false;
  const now = Date.now();
  if (Math.abs(now - Number(m[1])) > 2 * 60 * 1000 || usedNonces.has(m[2])) return false;
  if (!crypto.timingSafeEqual(Buffer.from(sign(m[1], m[2]), 'hex'), Buffer.from(m[3], 'hex'))) return false;
  for (const [nonce, at] of usedNonces) if (now - at > 5 * 60 * 1000) usedNonces.delete(nonce);
  usedNonces.set(m[2], now);
  return true;
}

function drained(res) {
  return new Promise((resolve) => {
    const done = () => { res.off('drain', done); res.off('close', done); resolve(); };
    res.on('drain', done);
    res.on('close', done);
  });
}

// Each file goes as a JSON header line followed by its bytes; an end line
// closes the set, so a cut-off transfer is never mistaken for a whole one.
async function send(res, files) {
  res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Cache-Control': 'no-store' });
  let count = 0;
  let total = 0;
  for (const file of files) {
    if (res.destroyed) return;
    let data = file.data;
    if (!data) {
      try { data = fs.readFileSync(file.abs); } catch (e) { continue; }
    }
    if (data.length > MAX_FILE_BYTES || total + data.length > MAX_TOTAL_BYTES) continue;
    total += data.length;
    res.write(JSON.stringify({ p: file.rel, n: data.length }) + '\n');
    if (!res.write(data)) await drained(res);
    count++;
  }
  res.end(JSON.stringify({ end: true, files: count }) + '\n');
}

function removeDir(dir) {
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch (e) { /* nothing there */ }
}

function pullOnce(base) {
  removeDir(INCOMING_DIR);
  fs.mkdirSync(INCOMING_DIR, { recursive: true });

  return new Promise((resolve) => {
    let settled = false;
    let req = null;
    let files = 0;
    let bytes = 0;
    const finish = (ok, reason, retry) => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      if (!ok) {
        if (req) req.destroy();
        removeDir(INCOMING_DIR);
        return resolve({ ok: false, reason, retry: !!retry });
      }
      try {
        const old = DATA_DIR + '.old';
        removeDir(old);
        if (fs.existsSync(DATA_DIR)) fs.renameSync(DATA_DIR, old);
        fs.renameSync(INCOMING_DIR, DATA_DIR);
        removeDir(old);
        resolve({ ok: true, files, bytes });
      } catch (e) {
        removeDir(INCOMING_DIR);
        resolve({ ok: false, reason: 'could not swap data/ in' });
      }
    };
    const deadline = setTimeout(() => finish(false, 'took too long', true), 120 * 1000);

    const stamp = String(Date.now());
    const nonce = crypto.randomBytes(16).toString('hex');
    const url = new URL(SYNC_PATH, base);
    req = (url.protocol === 'https:' ? https : http).request(url, {
      method: 'POST',
      headers: {
        [SYNC_HEADER]: stamp + '.' + nonce + '.' + sign(stamp, nonce),
        'Content-Length': 0,
        'User-Agent': 'soul-studies',
      },
      timeout: 8 * 1000,
    }, (res) => {
      if (res.statusCode !== 200) {
        res.resume();
        return finish(false, 'answered ' + res.statusCode, res.statusCode >= 500 || res.statusCode === 429);
      }
      let buf = Buffer.alloc(0);
      let fd = null;
      let remaining = 0;
      let ended = false;
      let received = 0;
      res.on('data', (chunk) => {
        if (settled) return;
        received += chunk.length;
        if (received > MAX_TOTAL_BYTES + 16 * 1024 * 1024) return finish(false, 'too large');
        buf = buf.length ? Buffer.concat([buf, chunk]) : chunk;
        try {
          while (buf.length && !ended) {
            if (fd !== null) {
              const take = Math.min(remaining, buf.length);
              fs.writeSync(fd, buf, 0, take);
              remaining -= take;
              bytes += take;
              buf = buf.subarray(take);
              if (remaining === 0) { fs.closeSync(fd); fd = null; files++; }
              continue;
            }
            const nl = buf.indexOf(10);
            if (nl === -1) {
              if (buf.length > 4096) throw new Error('header');
              break;
            }
            const head = JSON.parse(buf.subarray(0, nl).toString('utf8'));
            buf = buf.subarray(nl + 1);
            if (head && head.end === true) { ended = true; break; }
            if (!head || typeof head.p !== 'string' || !REL_PATH_RE.test(head.p) || head.p.split('/').includes('..') ||
                !Number.isInteger(head.n) || head.n < 0 || head.n > MAX_FILE_BYTES) throw new Error('header');
            const dest = path.join(INCOMING_DIR, head.p);
            fs.mkdirSync(path.dirname(dest), { recursive: true });
            fd = fs.openSync(dest, 'w', 0o600);
            remaining = head.n;
            if (remaining === 0) { fs.closeSync(fd); fd = null; files++; }
          }
        } catch (e) {
          if (fd !== null) { try { fs.closeSync(fd); } catch (e2) { /* gone */ } fd = null; }
          finish(false, 'unreadable transfer');
        }
      });
      res.on('end', () => (ended && fd === null ? finish(true) : finish(false, 'cut off', true)));
      res.on('error', () => finish(false, 'cut off', true));
      res.on('aborted', () => finish(false, 'cut off', true));
    });
    req.on('timeout', () => { req.destroy(); finish(false, 'no answer', true); });
    req.on('error', (e) => finish(false, 'unreachable (' + (e.code || e.message) + ')', true));
    req.end();
  });
}

async function pull() {
  const base = process.env.RENDER_EXTERNAL_URL || process.env.SOUL_STUDIES_SYNC_FROM || '';
  if (!SYNC_KEY || !/^https?:\/\//.test(base)) return { ok: false, reason: 'off' };
  let result = await pullOnce(base);
  if (!result.ok && result.retry) {
    await new Promise((r) => setTimeout(r, 1500));
    result = await pullOnce(base);
  }
  return result;
}

module.exports = { SYNC_PATH, accepts, send };

if (require.main === module) {
  pull()
    .then((r) => {
      if (r.ok) {
        console.log('[soul-studies] Picked up data/ from the instance being replaced: ' + r.files + ' files, ' +
          (r.bytes / 1048576).toFixed(1) + ' MB.');
      } else if (r.reason !== 'off') {
        console.log('[soul-studies] Nothing handed over (' + r.reason + '); starting from what is on disk.');
      }
    })
    .catch(() => {})
    .then(() => require('./server.js'));
}
