'use strict';
// End-to-end test: spins up the server on a random port with a temp data dir, then exercises accounts + rooms.
process.env.PORT = '0'; process.env.DATA_DIR = require('fs').mkdtempSync(require('os').tmpdir() + '/tfz-'); process.env.TRUST_PROXY = '1';
const { server } = require('./server.js');
let fails = 0; const ok = (c, m) => { console.log((c ? 'PASS ' : 'FAIL ') + m); if (!c) fails++; };
const sleep = ms => new Promise(r => setTimeout(r, ms));
server.listen(0, async () => {
  const base = 'http://127.0.0.1:' + server.address().port;
  const call = async (m, p, body, tok, ip) => { const r = await fetch(base + p, { method: m, headers: Object.assign({ 'Content-Type': 'application/json', 'X-Forwarded-For': ip || '1.1.1.1' }, tok ? { Authorization: 'Bearer ' + tok } : {}), body: body ? JSON.stringify(body) : undefined }); return { s: r.status, j: await r.json().catch(() => ({})) }; };
  try {
    let r = await call('POST', '/api/register', { username: 'Alice_1', password: 'secret1' }); ok(r.s === 200 && r.j.token, 'register Alice_1'); const ta = r.j.token;
    r = await call('POST', '/api/register', { username: 'alice_1', password: 'other123' }); ok(r.s === 409, 'duplicate username (different case) rejected: ' + r.j.error);
    r = await call('POST', '/api/register', { username: 'ab', password: 'secret1' }); ok(r.s === 400, 'too short username rejected');
    r = await call('POST', '/api/register', { username: 'bad name!', password: 'secret1' }); ok(r.s === 400, 'bad characters rejected');
    r = await call('POST', '/api/register', { username: 'Admin', password: 'secret1' }); ok(r.s === 400, 'reserved name rejected');
    r = await call('POST', '/api/register', { username: 'Newbie', password: '123' }); ok(r.s === 400, 'short password rejected');
    r = await call('GET', '/api/check?name=alice_1'); ok(r.j.available === false, 'check: taken name unavailable');
    r = await call('GET', '/api/check?name=FreshName'); ok(r.j.available === true, 'check: fresh name available');
    r = await call('POST', '/api/login', { username: 'ALICE_1', password: 'wrongpass' }); ok(r.s === 401, 'wrong password rejected');
    r = await call('POST', '/api/login', { username: 'nobody', password: 'wrongpass' }); ok(r.s === 401 && r.j.error === 'Wrong username or password', 'unknown user gives same error');
    r = await call('POST', '/api/login', { username: 'alice_1', password: 'secret1' }); ok(r.s === 200 && r.j.username === 'Alice_1', 'login is case-insensitive, keeps display name');
    r = await call('PUT', '/api/profile', { data: { tfz_vods: '1234', tfz_owned: '[0,1]', evil: 'x' } }, ta); ok(r.s === 200, 'save profile');
    r = await call('GET', '/api/profile', null, ta); ok(r.j.data && r.j.data.tfz_vods === '1234' && !('evil' in r.j.data), 'profile round-trips, foreign keys dropped');
    r = await call('GET', '/api/profile'); ok(r.s === 401, 'profile needs auth');
    r = await call('POST', '/api/register', { username: 'Bob', password: 'secret2' }, null, '2.2.2.2'); const tb = r.j.token; ok(!!tb, 'register Bob');
    r = await call('POST', '/api/register', { username: 'Cara', password: 'secret3' }, null, '3.3.3.3'); const tc = r.j.token;
    // rate limit on auth
    let lim = 0; for (let i = 0; i < 25; i++) { const x = await call('POST', '/api/login', { username: 'x', password: 'y' }, null, '9.9.9.9'); if (x.s === 429) lim++; } ok(lim > 0, 'auth rate limit kicks in');

    // websockets
    const wsUrl = t => base.replace('http', 'ws') + '/ws?token=' + t;
    const mk = t => new Promise((res, rej) => { const w = new WebSocket(wsUrl(t)); w.msgs = []; w.onmessage = e => w.msgs.push(JSON.parse(e.data)); w.onopen = () => res(w); w.onerror = () => rej(new Error('ws fail')); w.sj = o => w.send(JSON.stringify(o)); w.last = t2 => [...w.msgs].reverse().find(m => m.t === t2); });
    const bad = await new Promise(res => { const w = new WebSocket(wsUrl('nope')); w.onerror = () => res(true); w.onopen = () => res(false); setTimeout(() => res(true), 1500); }); ok(bad, 'ws without valid token refused');
    const A = await mk(ta), B = await mk(tb), C = await mk(tc); await sleep(100);
    ok(A.last('hello') && A.last('hello').name === 'Alice_1', 'ws hello');
    A.sj({ t: 'create', skin: 3, max: 3 }); await sleep(100);
    const room = A.last('room'); ok(room && room.code.length === 5 && room.players.length === 1, 'room created: ' + (room && room.code));
    B.sj({ t: 'join', code: room.code.toLowerCase(), skin: 1 }); await sleep(100);
    ok(A.last('room').players.length === 2, 'Bob joined by (lower-case) code');
    C.sj({ t: 'join', code: 'ZZZZZ', skin: 0 }); await sleep(80); ok(C.last('err') && /No room/.test(C.last('err').m), 'bad code error');
    B.sj({ t: 'start' }); await sleep(60); ok(!A.last('start'), 'non-host cannot start');
    A.sj({ t: 'start' }); await sleep(120); ok(A.last('start') && B.last('start') && A.last('start').players.length === 2, 'host starts, both get start');
    const sid = A.last('hello').id;
    A.sj({ t: 's', x: 3, z: -2, vx: 1, vz: 0, stam: 300, mx: 400 }); await sleep(80);
    const rel = B.last('s'); ok(rel && rel.id === sid && rel.x === 3 && rel.stam === 300, 'state relayed to the other player');
    ok(!A.last('s'), 'state not echoed to sender');
    B.sj({ t: 'h', to: sid, d: 12, kx: 5, kz: 0 }); await sleep(80); const hh = A.last('h'); ok(hh && hh.d === 12, 'hit relayed to victim');
    A.sj({ t: 'h', to: 99999, d: 12 }); await sleep(50);
    B.sj({ t: 'out' }); await sleep(150);
    const end = A.last('end'); ok(end && end.results[0].name === 'Alice_1' && end.results[0].place === 1 && end.results[1].place === 2, 'match ends when one left; winner Alice');
    ok(end && end.reward[sid] > end.reward[B.last('hello').id], 'winner reward > loser reward');
    await sleep(1700); ok(A.last('room').state === 'lobby', 'room returns to lobby');
    // quick match
    C.sj({ t: 'quick', skin: 2 }); await sleep(100); ok(C.last('room') && C.last('room').code !== room.code, 'quick match makes/join a public room');
    A.close(); B.close(); C.close();
    const lb = await call('GET', '/api/leaderboard', null, ta); ok(Array.isArray(lb.j.top), 'leaderboard works (matches under 15s do not count: top=' + lb.j.top.length + ')');
  } catch (e) { console.log('ERROR', e); fails++; }
  console.log(fails ? fails + ' FAILED' : 'ALL PASSED'); process.exit(fails ? 1 : 0);
});
