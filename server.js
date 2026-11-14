'use strict';
/*  Top Fight Zone 3D - game server
 *  - serves the game (public/index.html)
 *  - accounts with UNIQUE usernames (case-insensitive), scrypt-hashed passwords, bearer-token sessions
 *  - cloud save of the player's progress, leaderboard
 *  - live multiplayer rooms over a hand-written WebSocket (no npm packages needed)
 *
 *  env:  PORT (3000)   DATA_DIR (./data)   TRUST_PROXY=1 (behind nginx/Render/etc.)   ALLOWED_ORIGIN (only if the page is hosted on a different domain)
 */
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');

const PORT = process.env.PORT === undefined ? 3000 : +process.env.PORT;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '';
const PUBLIC_DIR = path.join(__dirname, 'public');
const MAX_PLAYERS = 6, MATCH_MAX_MS = 240000, AUTO_START_MS = 10000;

/* ------------------------------------------------------------------ storage */
fs.mkdirSync(DATA_DIR, { recursive: true });
const DB_FILE = path.join(DATA_DIR, 'users.json');
let db = { users: {}, sessions: {} };
try { db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch (e) { /* first run */ }
db.users = db.users || {}; db.sessions = db.sessions || {};
let dirty = false;
const saveSoon = () => { dirty = true; };
function flush() {
  if (!dirty) return; dirty = false;
  try { const tmp = DB_FILE + '.tmp'; fs.writeFileSync(tmp, JSON.stringify(db)); fs.renameSync(tmp, DB_FILE); } catch (e) { console.error('save failed', e.message); dirty = true; }
}
const flushTimer = setInterval(flush, 2000); flushTimer.unref();
function shutdown() { flush(); process.exit(0); }
process.on('SIGINT', shutdown); process.on('SIGTERM', shutdown);

/* ------------------------------------------------------------------ helpers */
const RESERVED = new Set(['admin', 'administrator', 'moderator', 'mod', 'system', 'server', 'guest', 'root', 'support', 'staff', 'owner', 'null', 'undefined', 'anonymous']);
const NAME_RE = /^[A-Za-z0-9_]{3,16}$/;
const nameError = n => typeof n !== 'string' ? 'Enter a username'
  : !NAME_RE.test(n) ? 'Username must be 3-16 letters, numbers or _'
    : RESERVED.has(n.toLowerCase()) ? 'That username is reserved' : null;
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
function scrypt(pw, salt) { return new Promise((res, rej) => crypto.scrypt(pw, salt, 64, (e, k) => e ? rej(e) : res(k))); }
async function hashPw(pw) { const salt = crypto.randomBytes(16); const k = await scrypt(pw, salt); return { salt: salt.toString('hex'), hash: k.toString('hex') }; }
async function checkPw(pw, u) { const k = await scrypt(pw, Buffer.from(u.salt, 'hex')); const h = Buffer.from(u.hash, 'hex'); return k.length === h.length && crypto.timingSafeEqual(k, h); }
const DUMMY = { salt: crypto.randomBytes(16).toString('hex'), hash: crypto.randomBytes(64).toString('hex') };

function newSession(lower) {
  const token = crypto.randomBytes(32).toString('hex');
  db.sessions[sha(token)] = { user: lower, exp: Date.now() + 30 * 864e5 };
  saveSoon(); return token;
}
function userFromToken(token) {
  if (!token || typeof token !== 'string') return null;
  const s = db.sessions[sha(token)]; if (!s) return null;
  if (s.exp < Date.now()) { delete db.sessions[sha(token)]; saveSoon(); return null; }
  const u = db.users[s.user]; return u ? { lower: s.user, u } : null;
}
setInterval(() => { const t = Date.now(); for (const k in db.sessions) if (db.sessions[k].exp < t) { delete db.sessions[k]; dirty = true; } }, 3600e3).unref();

const buckets = new Map();                               // tiny fixed-window rate limiter
function limited(key, max, ms) {
  const now = Date.now(); let b = buckets.get(key);
  if (!b || b.t < now) { b = { t: now + ms, n: 0 }; buckets.set(key, b); }
  return ++b.n > max;
}
setInterval(() => { const n = Date.now(); buckets.forEach((b, k) => { if (b.t < n) buckets.delete(k); }); }, 60e3).unref();
const ipOf = req => (TRUST_PROXY && String(req.headers['x-forwarded-for'] || '').split(',')[0].trim()) || req.socket.remoteAddress || '?';

/* ------------------------------------------------------------------ http */
function send(res, code, obj, extra) {
  const body = typeof obj === 'string' ? obj : JSON.stringify(obj);
  res.writeHead(code, Object.assign({ 'Content-Type': typeof obj === 'string' ? 'text/html; charset=utf-8' : 'application/json', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'same-origin' }, extra || {}));
  res.end(body);
}
function readJson(req, limit) {
  return new Promise((resolve, reject) => {
    let n = 0; const chunks = [];
    req.on('data', c => { n += c.length; if (n > limit) { reject(new Error('too big')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')); } catch (e) { reject(new Error('bad json')); } });
    req.on('error', reject);
  });
}
const bearer = req => { const h = req.headers.authorization || ''; return h.startsWith('Bearer ') ? h.slice(7) : ''; };
const publicStats = u => ({ wins: u.stats.wins, matches: u.stats.matches });

function cleanProfile(data) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) return null;
  const out = {}; let total = 0, count = 0;
  for (const k of Object.keys(data)) {
    if (!/^tfz_[A-Za-z0-9_]{1,60}$/.test(k) || typeof data[k] !== 'string' || data[k].length > 12000) continue;
    total += data[k].length + k.length; if (++count > 80 || total > 90000) return null;
    out[k] = data[k];
  }
  return out;
}

const api = {
  async 'POST /api/register'(req, res) {
    const b = await readJson(req, 4096), err = nameError(b.username);
    if (err) return send(res, 400, { error: err });
    if (typeof b.password !== 'string' || b.password.length < 6 || b.password.length > 72) return send(res, 400, { error: 'Password must be 6-72 characters' });
    const lower = b.username.toLowerCase();
    if (db.users[lower]) return send(res, 409, { error: 'That username is already taken' });
    const h = await hashPw(b.password);
    if (db.users[lower]) return send(res, 409, { error: 'That username is already taken' });          // re-check after the async hash
    db.users[lower] = { name: b.username, salt: h.salt, hash: h.hash, created: Date.now(), stats: { wins: 0, matches: 0 }, profile: null };
    const token = newSession(lower); saveSoon();
    send(res, 200, { token, username: b.username, stats: { wins: 0, matches: 0 }, hasProfile: false });
  },
  async 'POST /api/login'(req, res) {
    const b = await readJson(req, 4096);
    const u = typeof b.username === 'string' ? db.users[b.username.toLowerCase()] : null;
    const ok = await checkPw(typeof b.password === 'string' ? b.password.slice(0, 72) : '', u || DUMMY);
    if (!u || !ok) return send(res, 401, { error: 'Wrong username or password' });
    send(res, 200, { token: newSession(b.username.toLowerCase()), username: u.name, stats: publicStats(u), hasProfile: !!u.profile });
  },
  async 'POST /api/logout'(req, res) { const t = bearer(req); if (t && db.sessions[sha(t)]) { delete db.sessions[sha(t)]; saveSoon(); } send(res, 200, { ok: true }); },
  async 'GET /api/me'(req, res) { const a = userFromToken(bearer(req)); if (!a) return send(res, 401, { error: 'Not signed in' }); send(res, 200, { username: a.u.name, stats: publicStats(a.u), hasProfile: !!a.u.profile }); },
  async 'GET /api/profile'(req, res) { const a = userFromToken(bearer(req)); if (!a) return send(res, 401, { error: 'Not signed in' }); send(res, 200, { data: a.u.profile ? a.u.profile.data : null }); },
  async 'PUT /api/profile'(req, res) {
    const a = userFromToken(bearer(req)); if (!a) return send(res, 401, { error: 'Not signed in' });
    const b = await readJson(req, 110000), data = cleanProfile(b.data);
    if (!data) return send(res, 400, { error: 'Bad profile' });
    a.u.profile = { data, updated: Date.now() }; saveSoon(); send(res, 200, { ok: true });
  },
  async 'GET /api/check'(req, res, url) {
    const n = url.searchParams.get('name') || '', err = nameError(n);
    if (err) return send(res, 200, { available: false, reason: err });
    send(res, 200, { available: !db.users[n.toLowerCase()], reason: db.users[n.toLowerCase()] ? 'That username is already taken' : '' });
  },
  async 'GET /api/leaderboard'(req, res) {
    const all = Object.values(db.users).filter(u => u.stats.matches > 0).sort((a, b) => b.stats.wins - a.stats.wins || a.stats.matches - b.stats.matches || a.name.localeCompare(b.name));
    const a = userFromToken(bearer(req)); let me = null;
    if (a) { const i = all.indexOf(a.u); me = { rank: i < 0 ? null : i + 1, wins: a.u.stats.wins, matches: a.u.stats.matches }; }
    send(res, 200, { top: all.slice(0, 25).map((u, i) => ({ rank: i + 1, name: u.name, wins: u.stats.wins, matches: u.stats.matches })), me });
  }
};

let indexCache = null;
const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://x');
    if (ALLOWED_ORIGIN && req.headers.origin === ALLOWED_ORIGIN) {
      res.setHeader('Access-Control-Allow-Origin', ALLOWED_ORIGIN); res.setHeader('Vary', 'Origin');
      res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type'); res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, OPTIONS');
    }
    if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }
    if (url.pathname.startsWith('/api/')) {
      const h = api[req.method + ' ' + url.pathname];
      if (!h) return send(res, 404, { error: 'Not found' });
      const ip = ipOf(req), authy = url.pathname === '/api/register' || url.pathname === '/api/login';
      if (limited((authy ? 'a:' : 'g:') + ip, authy ? 20 : 240, 60000)) return send(res, 429, { error: 'Too many requests - wait a minute' });
      return await h(req, res, url);
    }
    if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
      if (!indexCache || process.env.NODE_ENV !== 'production') indexCache = fs.readFileSync(path.join(PUBLIC_DIR, 'index.html'), 'utf8');
      return send(res, 200, indexCache);
    }
    if (url.pathname === '/healthz') return send(res, 200, { ok: true });
    send(res, 404, { error: 'Not found' });
  } catch (e) {
    if (!res.headersSent) send(res, e && (e.message === 'bad json' || e.message === 'too big') ? 400 : 500, { error: e && e.message === 'bad json' ? 'Bad request' : 'Server error' });
  }
});

/* ------------------------------------------------------------------ websocket (RFC 6455, just what we need) */
const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11', WS_MAX = 64 * 1024;
function frame(str, op) {
  const p = Buffer.from(str), n = p.length; let h;
  if (n < 126) { h = Buffer.alloc(2); h[1] = n; } else if (n < 65536) { h = Buffer.alloc(4); h[1] = 126; h.writeUInt16BE(n, 2); } else { h = Buffer.alloc(10); h[1] = 127; h.writeBigUInt64BE(BigInt(n), 2); }
  h[0] = 0x80 | (op || 1); return Buffer.concat([h, p]);
}
class Conn {
  constructor(socket, onMsg, onClose) {
    this.s = socket; this.buf = Buffer.alloc(0); this.frag = []; this.fragLen = 0; this.fragOp = 0; this.closed = false; this.alive = true; this.rate = { t: 0, n: 0 };
    this.onMsg = onMsg; this.onClose = onClose;
    socket.setNoDelay(true);
    socket.on('data', d => { this.buf = Buffer.concat([this.buf, d]); try { this.parse(); } catch (e) { this.close(); } });
    socket.on('close', () => this.end()); socket.on('error', () => this.end());
  }
  parse() {
    for (; ;) {
      const b = this.buf; if (b.length < 2) return;
      const fin = !!(b[0] & 0x80), op = b[0] & 0x0f, masked = !!(b[1] & 0x80); let len = b[1] & 0x7f, off = 2;
      if (len === 126) { if (b.length < 4) return; len = b.readUInt16BE(2); off = 4; }
      else if (len === 127) { if (b.length < 10) return; const big = b.readBigUInt64BE(2); if (big > BigInt(WS_MAX)) return this.close(); len = Number(big); off = 10; }
      if (!masked || len > WS_MAX) return this.close();
      if (b.length < off + 4 + len) return;
      const mask = b.subarray(off, off + 4), data = Buffer.from(b.subarray(off + 4, off + 4 + len));
      for (let i = 0; i < len; i++) data[i] ^= mask[i & 3];
      this.buf = b.subarray(off + 4 + len);
      if (op === 8) return this.close();
      if (op === 9) { this.raw(frame(data, 10)); continue; }
      if (op === 10) { this.alive = true; continue; }
      if (op === 1 || op === 2) { this.fragOp = op; this.frag = [data]; this.fragLen = len; }
      else if (op === 0) { this.frag.push(data); this.fragLen += len; if (this.fragLen > WS_MAX) return this.close(); }
      else return this.close();
      if (fin) {
        const m = Buffer.concat(this.frag); this.frag = []; this.fragLen = 0;
        if (this.fragOp === 1) {
          const now = Date.now(); if (now - this.rate.t > 1000) { this.rate.t = now; this.rate.n = 0; }
          if (++this.rate.n > 90) { this.close(); return; }                       // flood protection
          this.onMsg(m.toString('utf8'));
        }
      }
    }
  }
  raw(buf) { if (!this.closed && this.s.writable) this.s.write(buf); }
  send(obj) { this.raw(frame(JSON.stringify(obj))); }
  close() { if (this.closed) return; try { this.s.write(Buffer.from([0x88, 0x00])); } catch (e) { } try { this.s.end(); } catch (e) { } this.end(); setTimeout(() => { try { this.s.destroy(); } catch (e) { } }, 500).unref(); }
  end() { if (this.closed) return; this.closed = true; this.onClose(); }
}

/* ------------------------------------------------------------------ rooms */
const rooms = new Map(), online = new Map();            // online: lower username -> player
let nextId = 1;
const CODE_CH = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
function newCode() { for (; ;) { let c = ''; for (let i = 0; i < 5; i++) c += CODE_CH[crypto.randomInt(CODE_CH.length)]; if (!rooms.has(c)) return c; } }
const num = (v, lim, d) => (typeof v === 'number' && isFinite(v)) ? Math.max(-lim, Math.min(lim, v)) : (d || 0);
const toRoom = (r, obj) => r.players.forEach(p => p.conn.send(obj));
const toOthers = (r, from, obj) => { const s = JSON.stringify(obj); r.players.forEach(p => { if (p !== from) p.conn.raw(frame(s)); }); };

function roomInfo(r) {
  return { t: 'room', code: r.code, host: r.host, pub: r.pub, max: r.max, state: r.state, autoIn: r.autoAt ? Math.max(0, r.autoAt - Date.now()) : 0, players: [...r.players.values()].map(p => ({ id: p.id, name: p.name, skin: p.skin })) };
}
function pushRoom(r) { toRoom(r, roomInfo(r)); scheduleAuto(r); }
function scheduleAuto(r) {
  clearTimeout(r.autoTimer); r.autoTimer = null; r.autoAt = 0;
  if (r.state === 'lobby' && r.pub && r.players.size >= 2) { r.autoAt = Date.now() + AUTO_START_MS; r.autoTimer = setTimeout(() => startMatch(r), AUTO_START_MS); }
  // (the countdown value is sent along with the next room update; clients read autoAt)
}
function createRoom(p, pub, max) {
  const r = { code: newCode(), host: p.id, pub: !!pub, max: Math.max(2, Math.min(MAX_PLAYERS, max | 0 || MAX_PLAYERS)), state: 'lobby', players: new Map(), autoTimer: null, autoAt: 0, endTimer: null, alive: new Set(), startedAt: 0, placed: [] };
  rooms.set(r.code, r); joinRoom(p, r); return r;
}
function joinRoom(p, r) { p.room = r; r.players.set(p.id, p); pushRoom(r); }
function leaveRoom(p) {
  const r = p.room; if (!r) return; p.room = null; r.players.delete(p.id);
  if (r.state === 'playing' && r.alive.has(p.id)) eliminate(r, p);
  if (!r.players.size) { clearTimeout(r.autoTimer); clearTimeout(r.endTimer); rooms.delete(r.code); return; }
  if (r.host === p.id) r.host = r.players.values().next().value.id;
  if (r.state === 'lobby' || r.state === 'playing') pushRoom(r);
}
function startMatch(r) {
  clearTimeout(r.autoTimer); r.autoTimer = null; r.autoAt = 0;
  if (r.state !== 'lobby' || r.players.size < 2) return;
  r.state = 'playing'; r.startedAt = Date.now(); r.placed = []; r.alive = new Set(r.players.keys());
  let slot = 0; const list = [...r.players.values()].map(p => { p.slot = slot++; p.st = 1; return { id: p.id, name: p.name, skin: p.skin, slot: p.slot }; });
  toRoom(r, { t: 'start', n: list.length, players: list, countdown: 3 });
  r.endTimer = setTimeout(() => finish(r, true), MATCH_MAX_MS + 4000);
}
function eliminate(r, p) {
  if (!r.alive.has(p.id)) return;
  r.alive.delete(p.id); const place = r.alive.size + 1; r.placed.push({ id: p.id, name: p.name, place });
  toRoom(r, { t: 'out', id: p.id, place });
  if (r.alive.size <= 1) finish(r, false);
}
function finish(r, timeout) {
  if (r.state !== 'playing') return; r.state = 'over'; clearTimeout(r.endTimer);
  const n = r.placed.length + r.alive.size;
  if (timeout && r.alive.size > 1) {                    // time up: most stamina left wins
    const rest = [...r.alive].map(id => r.players.get(id)).filter(Boolean).sort((a, b) => (b.st || 0) - (a.st || 0));
    rest.forEach((p, i) => { r.alive.delete(p.id); r.placed.push({ id: p.id, name: p.name, place: i + 1 }); });
  } else r.alive.forEach(id => { const p = r.players.get(id); r.placed.push({ id, name: p ? p.name : '?', place: 1 }); });
  r.alive.clear();
  const results = r.placed.slice().sort((a, b) => a.place - b.place), long = Date.now() - r.startedAt > 15000, reward = {};
  results.forEach(x => { reward[x.id] = x.place === 1 ? 150 + 25 * (n - 1) : Math.max(20, 60 - 15 * (x.place - 1)); });
  if (long && n >= 2) results.forEach(x => { const u = db.users[String(x.name).toLowerCase()]; if (u) { u.stats.matches++; if (x.place === 1) u.stats.wins++; } });
  saveSoon();
  toRoom(r, { t: 'end', results, reward });
  setTimeout(() => { if (r.state === 'over') { r.state = 'lobby'; if (r.players.size) pushRoom(r); } }, 1500);
}
function quick(p, skin) {
  for (const r of rooms.values()) if (r.pub && r.state === 'lobby' && r.players.size < r.max) { p.skin = skin; return joinRoom(p, r); }
  createRoom(p, true, MAX_PLAYERS);
}

function onMessage(p, text) {
  let m; try { m = JSON.parse(text); } catch (e) { return; }
  if (!m || typeof m.t !== 'string') return;
  const skin = Number.isInteger(m.skin) && m.skin >= 0 && m.skin < 80 ? m.skin : p.skin;
  switch (m.t) {
    case 'quick': if (p.room) return; p.skin = skin; return quick(p, skin);
    case 'create': if (p.room) return; p.skin = skin; return void createRoom(p, false, m.max);
    case 'join': {
      if (p.room) return; const r = rooms.get(String(m.code || '').toUpperCase().trim());
      if (!r) return p.conn.send({ t: 'err', m: 'No room with that code' });
      if (r.state !== 'lobby') return p.conn.send({ t: 'err', m: 'That match already started' });
      if (r.players.size >= r.max) return p.conn.send({ t: 'err', m: 'That room is full' });
      p.skin = skin; return joinRoom(p, r);
    }
    case 'leave': return leaveRoom(p);
    case 'skin': if (p.room && p.room.state === 'lobby') { p.skin = skin; pushRoom(p.room); } return;
    case 'start': { const r = p.room; if (!r || r.host !== p.id || r.state !== 'lobby') return; if (r.players.size < 2) return p.conn.send({ t: 'err', m: 'Need at least 2 players' }); return startMatch(r); }
    case 's': {
      const r = p.room; if (!r || r.state !== 'playing' || !r.alive.has(p.id)) return;
      const mx = num(m.mx, 1e5), stam = Math.max(0, num(m.stam, 1e5));
      p.st = mx > 0 ? Math.min(1, stam / mx) : p.st;
      const o = { t: 's', id: p.id, x: num(m.x, 80), z: num(m.z, 80), vx: num(m.vx, 80), vz: num(m.vz, 80), stam: stam, mx: mx };
      return toOthers(r, p, o);
    }
    case 'h': {
      const r = p.room; if (!r || r.state !== 'playing' || !r.alive.has(p.id)) return;
      const now = Date.now(); if (now - (p.hitT || 0) > 1000) { p.hitT = now; p.hitN = 0; } if (++p.hitN > 14) return;
      const v = r.players.get(m.to | 0); if (!v || v === p || !r.alive.has(v.id)) return;
      return v.conn.send({ t: 'h', from: p.id, d: Math.max(0, Math.min(60, num(m.d, 60))), kx: num(m.kx, 40), kz: num(m.kz, 40) });
    }
    case 'out': { const r = p.room; if (r && r.state === 'playing') eliminate(r, p); return; }
  }
}

server.on('upgrade', (req, socket) => {
  try {
    const url = new URL(req.url, 'http://x');
    const origin = req.headers.origin;
    if (url.pathname !== '/ws' || (origin && origin !== 'http://' + req.headers.host && origin !== 'https://' + req.headers.host && origin !== ALLOWED_ORIGIN)) return void socket.destroy();
    const a = userFromToken(url.searchParams.get('token')), key = req.headers['sec-websocket-key'];
    if (!a || !key || limited('w:' + ipOf(req), 30, 60000)) { socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n'); return void socket.destroy(); }
    socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + crypto.createHash('sha1').update(key + WS_GUID).digest('base64') + '\r\n\r\n');
    const old = online.get(a.lower); if (old) { old.conn.send({ t: 'err', m: 'Signed in from another tab' }); old.conn.close(); }
    const p = { id: nextId++, name: a.u.name, lower: a.lower, room: null, skin: 0, st: 1 };
    p.conn = new Conn(socket, text => onMessage(p, text), () => { leaveRoom(p); if (online.get(a.lower) === p) online.delete(a.lower); });
    online.set(a.lower, p);
    p.conn.send({ t: 'hello', id: p.id, name: p.name, online: online.size });
  } catch (e) { try { socket.destroy(); } catch (e2) { } }
});
setInterval(() => online.forEach(p => { if (!p.conn.alive) return p.conn.close(); p.conn.alive = false; p.conn.raw(frame('', 9)); }), 25000).unref();

if (require.main === module) {
  server.listen(PORT, () => console.log('Top Fight Zone server on http://localhost:' + server.address().port));
}
module.exports = { server, db, rooms };
