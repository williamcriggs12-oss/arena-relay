
'use strict';
// Arena FPS relay server. Zero dependencies (Node 18+).
// Each client sends presence patches; the server merges them, validates, and broadcasts diffs to lobby-mates.
const http = require('http');
const { URL } = require('url');
const { handshake } = require('./ws-lite');

const ENV = process.env;
const num = (v, d) => (v !== undefined && v !== '' && !isNaN(+v) ? +v : d);

function start(opts = {}) {
  const C = {
    port: opts.port ?? num(ENV.PORT, 8080),
    host: opts.host ?? ENV.HOST ?? '0.0.0.0',
    maxPlayers: opts.maxPlayers ?? num(ENV.MAX_PLAYERS, 12),
    maxLobbies: opts.maxLobbies ?? num(ENV.MAX_LOBBIES, 500),
    maxPerIp: opts.maxPerIp ?? num(ENV.MAX_CONN_PER_IP, 6),
    origins: opts.origins ?? (ENV.ALLOWED_ORIGINS ? ENV.ALLOWED_ORIGINS.split(',').map(s => s.trim()).filter(Boolean) : []),
    trustProxy: opts.trustProxy ?? (ENV.TRUST_PROXY === '1' || ENV.TRUST_PROXY === 'true'),
    tickMs: opts.tickMs ?? 50,
    maxMsg: 8192,
    stateMax: 4096,
    heartbeatMs: opts.heartbeatMs ?? 20000,
  };

  const lobbies = new Map(); // key -> Lobby
  const ipCount = new Map();
  let nextId = 1;
  const stats = { connections: 0, totalConnections: 0, messages: 0, rejected: 0, started: Date.now() };

  class Lobby {
    constructor(key, priv) { this.key = key; this.priv = priv; this.peers = new Map(); this.dirty = new Set(); this.left = []; }
  }

  // ---------- sanitising ----------
  const BAD = new Set(['__proto__', 'constructor', 'prototype']);
  function clean(v, depth) {
    if (v === null) return null;
    const t = typeof v;
    if (t === 'number') return isFinite(v) ? v : 0;
    if (t === 'boolean') return v;
    if (t === 'string') return v.length > 256 ? v.slice(0, 256) : v;
    if (depth > 8) return undefined;
    if (Array.isArray(v)) {
      const out = [];
      for (let i = 0; i < v.length && i < 40; i++) { const c = clean(v[i], depth + 1); out.push(c === undefined ? null : c); }
      return out;
    }
    if (t === 'object') {
      const out = {}; let n = 0;
      for (const k of Object.keys(v)) {
        if (BAD.has(k) || k.length > 24) continue;
        if (++n > 120) break;
        const c = clean(v[k], depth + 1);
        if (c !== undefined) out[k] = c;
      }
      return out;
    }
    return undefined;
  }

  // ---------- guards ----------
  function bucket(p, name, rate, burst) {
    const b = p.buckets[name] || (p.buckets[name] = { t: burst, at: Date.now() });
    const now = Date.now();
    b.t = Math.min(burst, b.t + (now - b.at) / 1000 * rate); b.at = now;
    return b;
  }
  const inR = (v, lo, hi) => typeof v === 'number' && v >= lo && v <= hi;
  function guard(p, patch) {
    const st = p.state;
    for (const k of ['x', 'z', 'fx', 'fz']) if (k in patch && patch[k] !== null && !inR(patch[k], -80, 80)) delete patch[k];
    for (const k of ['y', 'fy']) if (k in patch && patch[k] !== null && !inR(patch[k], -10, 100)) delete patch[k];
    // monotonic counters may only grow at a human rate
    for (const [k, rate, burst] of [['k', 3, 3], ['d', 3, 3], ['kl', 2, 3]]) {
      if (!(k in patch)) continue;
      const nv = patch[k], ov = st[k];
      if (typeof nv !== 'number') { if (nv !== null) delete patch[k]; continue; }
      if (typeof ov === 'number' && nv > ov) {
        const b = bucket(p, k, rate, burst), inc = nv - ov;
        if (inc > b.t) { patch[k] = ov + Math.floor(Math.max(0, b.t)); b.t -= Math.max(0, Math.floor(b.t)); } else b.t -= inc;
      } else if (typeof ov !== 'number' && nv > 3) patch[k] = 3;
    }
    if ('hq' in patch && patch.hq && typeof patch.hq === 'object' && !Array.isArray(patch.hq)) {
      const old = (st.hq && typeof st.hq === 'object') ? st.hq : {};
      const b = bucket(p, 'hq', 450, 150);
      for (const id of Object.keys(patch.hq)) {
        const nv = patch.hq[id], ov = typeof old[id] === 'number' ? old[id] : 0;
        if (typeof nv !== 'number') { delete patch.hq[id]; continue; }
        if (nv > ov) {
          const inc = nv - ov;
          if (inc > b.t) { patch.hq[id] = ov + Math.max(0, Math.floor(b.t)); b.t = Math.max(0, b.t - Math.floor(b.t)); } else b.t -= inc;
        }
      }
    }
  }

  function applyPatch(p, patch) {
    const s = p.state;
    const next = Object.assign({}, s);
    for (const k of Object.keys(patch)) { if (patch[k] === null) delete next[k]; else next[k] = patch[k]; }
    if (Object.keys(next).length > 120) return 'too many keys';
    if (Buffer.byteLength(JSON.stringify(next)) > C.stateMax) return 'state too large';
    p.state = next;
    return null;
  }

  // ---------- lobby mgmt ----------
  function pickLobby(room, mode, map) {
    if (room) {
      const key = 'r:' + room;
      let l = lobbies.get(key);
      if (!l) {
        if (lobbies.size >= C.maxLobbies) return { err: [4002, 'server busy'] };
        l = new Lobby(key, true); lobbies.set(key, l);
      }
      if (l.peers.size >= C.maxPlayers) return { err: [4001, 'room full'] };
      return { l };
    }
    const base = mode + ':' + map;
    let best = null;
    for (const l of lobbies.values()) if (!l.priv && l.key.startsWith(base + '#') && l.peers.size < C.maxPlayers) {
      if (!best || l.peers.size > best.peers.size) best = l;
    }
    if (best) return { l: best };
    if (lobbies.size >= C.maxLobbies) return { err: [4002, 'server busy'] };
    const l = new Lobby(base + '#' + (nextId++), false); lobbies.set(l.key, l);
    return { l };
  }

  function clientIp(req) {
    if (C.trustProxy) {
      const x = req.headers['x-forwarded-for'];
      if (x) { const parts = String(x).split(','); return parts[parts.length - 1].trim(); }
    }
    return req.socket.remoteAddress || '?';
  }

  // ---------- http ----------
  const server = http.createServer((req, res) => {
    const path = (req.url || '/').split('?')[0];
    if (path === '/health') {
      let players = 0; for (const l of lobbies.values()) players += l.peers.size;
      res.writeHead(200, { 'content-type': 'application/json', 'access-control-allow-origin': '*' });
      return res.end(JSON.stringify({ ok: true, lobbies: lobbies.size, players, uptime: Math.round((Date.now() - stats.started) / 1000) }));
    }
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end('Arena FPS relay. Connect with a WebSocket.\n');
  });

  server.on('upgrade', (req, socket, head) => {
    socket.on('error', () => {});
    let u;
    try { u = new URL(req.url, 'http://x'); } catch (e) { return socket.destroy(); }
    if (u.pathname !== '/' && u.pathname !== '/ws') { socket.end('HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n'); return; }
    const origin = req.headers.origin;
    if (C.origins.length && origin && !C.origins.includes(origin)) { stats.rejected++; socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n'); return; }
    const ip = clientIp(req);
    if ((ipCount.get(ip) || 0) >= C.maxPerIp) { stats.rejected++; socket.end('HTTP/1.1 429 Too Many Requests\r\nConnection: close\r\n\r\n'); return; }

    const roomQ = u.searchParams.get('room');
    const room = roomQ && /^[A-Za-z0-9_-]{1,16}$/.test(roomQ) ? roomQ : null;
    let mode = u.searchParams.get('mode') || 'ffa', map = u.searchParams.get('map') || '0';
    if (!/^[a-z0-9]{1,12}$/.test(mode)) mode = 'ffa';
    if (!/^[a-z0-9]{1,12}$/.test(map)) map = '0';

    const conn = handshake(req, socket, head, C.maxMsg);
    if (!conn) return;
    ipCount.set(ip, (ipCount.get(ip) || 0) + 1);
    stats.connections++; stats.totalConnections++;

    let released = false;
    function release() {
      if (released) return; released = true;
      const n = (ipCount.get(ip) || 1) - 1; if (n <= 0) ipCount.delete(ip); else ipCount.set(ip, n);
      stats.connections--;
    }

    const pick = pickLobby(room, mode, map);
    if (pick.err) {
      conn.close(pick.err[0], pick.err[1]);
      conn.on('close', () => release());
      return;
    }
    const lobby = pick.l;
    const id = 'p' + (nextId++).toString(36);
    const peer = { id, conn, state: {}, sent: new Map(), buckets: {}, msgs: { t: 160, at: Date.now() }, ip, joinedAt: Date.now() };
    lobby.peers.set(id, peer);
    // gets everything existing on the next tick
    peer.needFull = true;
    lobby.dirty.add(id);
    conn.send(JSON.stringify({ t: 'hello', id, lobby: lobby.key, priv: lobby.priv, max: C.maxPlayers, n: lobby.peers.size }));

    conn.on('message', text => {
      stats.messages++;
      const now = Date.now(), m = peer.msgs;
      m.t = Math.min(160, m.t + (now - m.at) / 1000 * 80); m.at = now;
      if (--m.t < 0) { stats.rejected++; return conn.close(4008, 'rate limit'); }
      let msg; try { msg = JSON.parse(text); } catch (e) { return; }
      if (!msg || typeof msg !== 'object') return;
      if (msg.t === 'ping') return void conn.send('{"t":"pong"}');
      if (msg.t !== 'p' || !msg.d || typeof msg.d !== 'object' || Array.isArray(msg.d)) return;
      const patch = clean(msg.d, 0);
      guard(peer, patch);
      const err = applyPatch(peer, patch);
      if (err) return void conn.send(JSON.stringify({ t: 'err', code: 'invalid_argument', message: err }));
      lobby.dirty.add(id);
    });

    conn.on('close', () => {
      release();
      if (lobby.peers.delete(id)) {
        lobby.dirty.delete(id);
        lobby.left.push(id);
        for (const o of lobby.peers.values()) o.sent.delete(id);
      }
    });
  });

  // ---------- broadcast ----------
  const tick = setInterval(() => {
    for (const [key, lobby] of lobbies) {
      if (!lobby.peers.size) { lobbies.delete(key); continue; }
      if (!lobby.dirty.size && !lobby.left.length && ![...lobby.peers.values()].some(p => !p.knows)) continue;
      const left = lobby.left; lobby.left = [];
      for (const r of lobby.peers.values()) {
        const first = !r.knows;
        r.knows = true;
        const u = {};
        for (const [pid, p] of lobby.peers) {
          if (pid === r.id) continue;
          if (!first && !lobby.dirty.has(pid)) continue;
          let seen = r.sent.get(pid);
          if (!seen) { seen = new Map(); r.sent.set(pid, seen); }
          const d = {}; let changed = false;
          for (const k of Object.keys(p.state)) {
            const j = JSON.stringify(p.state[k]);
            if (seen.get(k) !== j) { seen.set(k, j); d[k] = p.state[k]; changed = true; }
          }
          for (const k of Array.from(seen.keys())) if (!(k in p.state)) { seen.delete(k); d[k] = null; changed = true; }
          if (changed || first) u[pid] = d;
        }
        if (Object.keys(u).length || left.length || first) r.conn.send(JSON.stringify({ t: 's', u, l: left.filter(x => x !== r.id) }));
      }
      lobby.dirty.clear();
    }
  }, C.tickMs);

  const hb = setInterval(() => {
    for (const l of lobbies.values()) for (const p of l.peers.values()) {
      if (!p.conn.alive) { p.conn.terminate(); continue; }
      p.conn.alive = false; p.conn.ping();
    }
  }, C.heartbeatMs);

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(C.port, C.host, () => {
      const port = server.address().port;
      resolve({
        server, port, stats, lobbies,
        close() {
          clearInterval(tick); clearInterval(hb);
          for (const l of lobbies.values()) for (const p of l.peers.values()) p.conn.close(1001, 'server shutting down');
          return new Promise(r => { server.close(() => r()); setTimeout(r, 500); });
        },
      });
    });
  });
}

module.exports = { start };

if (require.main === module) {
  start().then(s => {
    console.log('Arena relay listening on :' + s.port);
    const bye = () => s.close().then(() => process.exit(0));
    process.on('SIGTERM', bye); process.on('SIGINT', bye);
  }).catch(e => { console.error(e); process.exit(1); });
}
