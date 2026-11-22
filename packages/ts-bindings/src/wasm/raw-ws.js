// A minimal RFC 6455 WebSocket client over `net.Socket` (test-only). A
// browser `WebSocket` cannot set an `Authorization` header, so this injects
// a header-capable transport to prove the DSR-44 design: the relay pairing
// room's capability rides in the header, exactly as `join_room` expects.
//
// Implements just enough of the protocol for the pairing exchange: text
// frames, ping/pong (auto-reply), and close. Client frames are masked per
// spec; server frames are accepted masked or not. Fragmentation is not
// needed (pairing frames are small) and rejected loudly.

import { connect } from "node:net";
import { randomBytes } from "node:crypto";

const OP_TEXT = 0x1;
const OP_CLOSE = 0x8;
const OP_PING = 0x9;
const OP_PONG = 0xa;

export class RawWebSocket {
  /**
   * @param {string} url ws://host:port/path
   * @param {{headers?: Record<string,string>}} options
   */
  constructor(url, options = {}) {
    this._url = new URL(url);
    this._headers = options.headers ?? {};
    this._socket = null;
    this._buffer = Buffer.alloc(0);
    this._opened = false;
    this._ended = false;
    this.readyState = 0; // CONNECTING
    this.onopen = null;
    this.onmessage = null;
    this.onclose = null;
    this.onerror = null;
  }

  connect() {
    const port = Number(this._url.port) || 80;
    const socket = connect(port, this._url.hostname);
    this._socket = socket;
    socket.on("error", (error) => {
      // A half-closed socket is not an error once we asked it to end: a
      // peer close arriving during that teardown would otherwise surface
      // as ERR_STREAM_WRITE_AFTER_END.
      if (this._ended) return;
      this._emit("error", error);
    });
    socket.on("close", () => {
      if (!this._opened) return;
      this.readyState = 3; // CLOSED
      this._emit("close");
    });
    socket.on("data", (chunk) => this._onData(chunk));

    const key = randomBytes(16).toString("base64");
    const path = this._url.pathname + this._url.search;
    const lines = [
      `GET ${path} HTTP/1.1`,
      `Host: ${this._url.hostname}:${port}`,
      "Upgrade: websocket",
      "Connection: Upgrade",
      `Sec-WebSocket-Key: ${key}`,
      "Sec-WebSocket-Version: 13",
    ];
    for (const [name, value] of Object.entries(this._headers)) {
      lines.push(`${name}: ${value}`);
    }
    socket.write(lines.join("\r\n") + "\r\n\r\n");
  }

  _emit(name, ...args) {
    const handler = this[`on${name}`];
    if (handler) handler(...args);
  }

  _onData(chunk) {
    this._buffer = Buffer.concat([this._buffer, chunk]);
    if (!this._opened) {
      const end = this._buffer.indexOf("\r\n\r\n");
      if (end === -1) return;
      const head = this._buffer.subarray(0, end).toString("utf8");
      this._buffer = this._buffer.subarray(end + 4);
      const status = Number(head.split("\r\n")[0].split(" ")[1]);
      if (status !== 101) {
        this._emit("error", new Error(`upgrade failed: ${head.split("\r\n")[0]}`));
        this._socket.end();
        return;
      }
      this._opened = true;
      this.readyState = 1; // OPEN
      this._emit("open");
    }
    this._drainFrames();
  }

  _drainFrames() {
    while (true) {
      const frame = this._readFrame();
      if (!frame) return;
      const { opcode, payload } = frame;
      if (opcode === OP_PING) {
        this._writeFrame(OP_PONG, payload);
      } else if (opcode === OP_PONG) {
        // nothing to do
      } else if (opcode === OP_TEXT) {
        this._emit("message", payload.toString("utf8"));
      } else if (opcode === OP_CLOSE) {
        this.close();
        return;
      } else {
        this._emit("error", new Error(`unsupported ws opcode 0x${opcode.toString(16)}`));
        this._socket.end();
        return;
      }
    }
  }

  _readFrame() {
    if (this._buffer.length < 2) return null;
    const b0 = this._buffer[0];
    const b1 = this._buffer[1];
    const fin = (b0 & 0x80) !== 0;
    const opcode = b0 & 0x0f;
    const masked = (b1 & 0x80) !== 0;
    let len = b1 & 0x7f;
    let offset = 2;
    if (len === 126) {
      if (this._buffer.length < 4) return null;
      len = this._buffer.readUInt16BE(2);
      offset = 4;
    } else if (len === 127) {
      if (this._buffer.length < 10) return null;
      len = Number(this._buffer.readBigUInt64BE(2));
      offset = 10;
    }
    if (!fin && opcode !== OP_TEXT) {
      // Fragmentation is not needed for pairing frames; reject rather than
      // silently drop the tail.
      throw new Error("fragmented ws frame not supported");
    }
    let maskKey = null;
    if (masked) {
      if (this._buffer.length < offset + 4) return null;
      maskKey = this._buffer.subarray(offset, offset + 4);
      offset += 4;
    }
    if (this._buffer.length < offset + len) return null;
    let payload = this._buffer.subarray(offset, offset + len);
    if (maskKey) {
      const unmasked = Buffer.alloc(len);
      for (let i = 0; i < len; i++) unmasked[i] = payload[i] ^ maskKey[i & 3];
      payload = unmasked;
    }
    this._buffer = this._buffer.subarray(offset + len);
    return { opcode, payload };
  }

  _writeFrame(opcode, payload) {
    if (this._ended || !this._socket || this._socket.writableEnded) return;
    const len = payload.length;
    let header;
    if (len < 126) {
      header = Buffer.alloc(2);
      header[1] = 0x80 | len;
    } else if (len < 65536) {
      header = Buffer.alloc(4);
      header[1] = 0x80 | 126;
      header.writeUInt16BE(len, 2);
    } else {
      header = Buffer.alloc(10);
      header[1] = 0x80 | 127;
      header.writeBigUInt64BE(BigInt(len), 2);
    }
    header[0] = 0x80 | opcode;
    const mask = randomBytes(4);
    const masked = Buffer.alloc(len);
    for (let i = 0; i < len; i++) masked[i] = payload[i] ^ mask[i & 3];
    this._socket.write(Buffer.concat([header, mask, masked]));
  }

  send(text) {
    if (this.readyState !== 1) throw new Error("ws not open");
    this._writeFrame(OP_TEXT, Buffer.from(text, "utf8"));
  }

  close() {
    if (!this._socket || this._ended) return;
    this._ended = true;
    this.readyState = 3; // CLOSED
    this._socket.end();
  }
}

/** Open a RawWebSocket against a `ws://` URL derived from an `http://` base. */
export function openRawWebSocket(baseHttpUrl, path, headers) {
  const base = new URL(baseHttpUrl);
  const wsUrl = `ws://${base.host}${path}`;
  const socket = new RawWebSocket(wsUrl, { headers });
  socket.connect();
  return socket;
}
