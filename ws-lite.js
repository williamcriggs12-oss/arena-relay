'use strict';
// Minimal RFC 6455 WebSocket server side: handshake, text frames (incl. fragmentation), ping/pong, close.
// Zero dependencies. Messages are small JSON strings, so binary frames are refused.
const crypto = require('crypto');
const { EventEmitter } = require('events');
const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

function frame(op, payload) {
  const len = payload.length;
  let head;
  if (len < 126) { head = Buffer.alloc(2); head[1] = len; }
  else if (len < 65536) { head = Buffer.alloc(4); head[1] = 126; head.writeUInt16BE(len, 2); }
  else { head = Buffer.alloc(10); head[1] = 127; head.writeUInt32BE(0, 2); head.writeUInt32BE(len, 6); }
  head[0] = 0x80 | op;
  return Buffer.concat([head, payload]);
}

class Conn extends EventEmitter {
  constructor(socket, maxPayload) {
    super();
    this.socket = socket;
    this.max = maxPayload;
    this.buf = Buffer.alloc(0);
    this.frag = null;
    this.fragLen = 0;
    this.closed = false;
    this.closing = false;
    this.alive = true;
    this._done = false;
    socket.setNoDelay(true);
    socket.on('data', d => this._onData(d));
    socket.on('error', () => this.terminate());
    socket.on('close', () => this._finish());
    socket.on('end', () => { try { socket.end(); } catch (e) {} });
  }
  _onData(d) {
    if (this.closed || this.closing) return;
    this.buf = this.buf.length ? Buffer.concat([this.buf, d]) : d;
    this._parse();
  }
  _fail(code, reason) { this.close(code, reason); }
  _parse() {
    for (;;) {
      const b = this.buf;
      if (this.closed || this.closing || b.length < 2) return;
      const b0 = b[0], b1 = b[1];
      const fin = !!(b0 & 0x80), op = b0 & 0x0f, masked = !!(b1 & 0x80);
      if (b0 & 0x70) return this._fail(1002, 'rsv bits');
      if (!masked) return this._fail(1002, 'client frames must be masked');
      let len = b1 & 0x7f, off = 2;
      if (len === 126) { if (b.length < 4) return; len = b.readUInt16BE(2); off = 4; }
      else if (len === 127) {
        if (b.length < 10) return;
        const hi = b.readUInt32BE(2), lo = b.readUInt32BE(6);
        if (hi !== 0 || lo > this.max) return this._fail(1009, 'message too big');
        len = lo; off = 10;
      }
      if (len > this.max) return this._fail(1009, 'message too big');
      if (op >= 8 && (len > 125 || !fin)) return this._fail(1002, 'bad control frame');
      if (b.length < off + 4 + len) return;
      const mask = b.subarray(off, off + 4);
      const payload = Buffer.allocUnsafe(len);
      for (let i = 0; i < len; i++) payload[i] = b[off + 4 + i] ^ mask[i & 3];
      this.buf = b.subarray(off + 4 + len);
      this._frame(fin, op, payload);
    }
  }
  _frame(fin, op, payload) {
    switch (op) {
      case 1:
        if (this.frag) return this._fail(1002, 'unexpected text frame');
        if (fin) { this.alive = true; this.emit('message', payload.toString('utf8')); }
        else { this.frag = [payload]; this.fragLen = payload.length; }
        return;
      case 0:
        if (!this.frag) return this._fail(1002, 'unexpected continuation');
        this.fragLen += payload.length;
        if (this.fragLen > this.max) return this._fail(1009, 'message too big');
        this.frag.push(payload);
        if (fin) { const s = Buffer.concat(this.frag).toString('utf8'); this.frag = null; this.alive = true; this.emit('message', s); }
        return;
      case 2: return this._fail(1003, 'binary not supported');
      case 8: return this.close(1000, '');
      case 9: this.alive = true; this._write(frame(10, payload)); return;
      case 10: this.alive = true; this.emit('pong'); return;
      default: return this._fail(1002, 'unknown opcode');
    }
  }
  _write(buf) { if (!this.socket.destroyed && this.socket.writable) this.socket.write(buf); }
  send(str) {
    if (this.closed || this.closing) return false;
    if (this.socket.writableLength > 2 * 1024 * 1024) { this.terminate(); return false; } // client cannot keep up
    this._write(frame(1, Buffer.from(str)));
    return true;
  }
  ping() { if (!this.closed && !this.closing) this._write(frame(9, Buffer.alloc(0))); }
  close(code = 1000, reason = '') {
    if (this.closed || this.closing) return;
    this.closing = true;
    const r = Buffer.from(String(reason)).subarray(0, 100);
    const p = Buffer.alloc(2 + r.length);
    p.writeUInt16BE(code, 0); r.copy(p, 2);
    this._write(frame(8, p));
    try { this.socket.end(); } catch (e) {}
    this._kill = setTimeout(() => this.terminate(), 2000);
    if (this._kill.unref) this._kill.unref();
  }
  terminate() {
    this.closed = true;
    try { this.socket.destroy(); } catch (e) {}
    this._finish();
  }
  _finish() {
    if (this._done) return;
    this._done = true; this.closed = true;
    clearTimeout(this._kill);
    this.emit('close');
  }
}

// Returns a Conn after completing the upgrade, or null (and writes an HTTP error) when the request is not a valid WebSocket upgrade.
function handshake(req, socket, head, maxPayload) {
  const key = req.headers['sec-websocket-key'];
  if (!key || String(req.headers.upgrade || '').toLowerCase() !== 'websocket' || req.headers['sec-websocket-version'] !== '13') {
    socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
    return null;
  }
  const acc = crypto.createHash('sha1').update(key + GUID).digest('base64');
  socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + acc + '\r\n\r\n');
  const c = new Conn(socket, maxPayload);
  if (head && head.length) c._onData(head);
  return c;
}

module.exports = { handshake, frame };
