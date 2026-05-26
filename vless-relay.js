const dgram = require('dgram');
const net = require('net');

const CMD_TCP = 0x01;
const CMD_UDP = 0x02;
/** VLESS command 0x03 = Mux; XUDP is framed inside the body when command is Mux */
const CMD_MUX = 0x03;
const CMD_RVS = 0x04;

/**
 * Refer to: https://xray-internals.hidandelion.com/protocols/vless.html
 * Parse the client handshake message and extract the version, UUID, target host/port and message offset
 * @param {Buffer} buf
 * @returns {{version:number, id:Buffer, command:number, host:string, port:number, offset:number}}
 */
function parseHandshake(buf) {
    let offset = 0;
    const version = buf.readUInt8(offset);
    offset += 1;

    const id = buf.subarray(offset, offset + 16);
    offset += 16;

    const optLen = buf.readUInt8(offset);
    offset += 1 + optLen;

    const command = buf.readUInt8(offset);
    offset += 1;

    if (command === CMD_MUX || command === CMD_RVS) {
        return {version, id, command, host: '', port: 0, offset};
    }

    if (offset + 2 > buf.length) {
        throw new Error(`Handshake too short for port at offset ${offset} (${buf.length} bytes total)`);
    }

    const port = buf.readUInt16BE(offset);
    offset += 2;

    if (offset >= buf.length) {
        throw new Error(`Handshake too short for address type at offset ${offset}`);
    }

    const addressType = buf.readUInt8(offset);
    offset += 1;

    let host;
    if (addressType === 1) {
        host = Array.from(buf.subarray(offset, offset + 4)).join('.');
        offset += 4;
    } else if (addressType === 2) {
        const len = buf.readUInt8(offset++);
        host = buf.subarray(offset, offset + len).toString();
        offset += len;
    } else if (addressType === 3) {
        const segments = [];
        for (let i = 0; i < 8; i++) {
            segments.push(buf.readUInt16BE(offset).toString(16));
            offset += 2;
        }
        host = segments.join(':');
    } else {
        throw new Error(`Unsupported address type: ${addressType}`);
    }

    return {version, id, command, host, port, offset};
}

function readPortThenAddress(buf, offset) {
    const port = buf.readUInt16BE(offset);
    offset += 2;
    const addressType = buf.readUInt8(offset);
    offset += 1;

    let host;
    if (addressType === 1) {
        host = Array.from(buf.subarray(offset, offset + 4)).join('.');
        offset += 4;
    } else if (addressType === 2) {
        const len = buf.readUInt8(offset++);
        host = buf.subarray(offset, offset + len).toString();
        offset += len;
    } else if (addressType === 3) {
        const segments = [];
        for (let i = 0; i < 8; i++) {
            segments.push(buf.readUInt16BE(offset).toString(16));
            offset += 2;
        }
        host = segments.join(':');
    } else {
        throw new Error(`Unsupported address type: ${addressType}`);
    }

    return {host, port, offset};
}

function encodePortThenAddress(host, port) {
    const portBuf = Buffer.alloc(2);
    portBuf.writeUInt16BE(port, 0);

    if (net.isIP(host) === 4) {
        return Buffer.concat([portBuf, Buffer.from([0x01]), Buffer.from(host.split('.').map(Number))]);
    }
    if (net.isIP(host) === 6) {
        const addr = Buffer.alloc(16);
        const parts = host.includes('::') ? expandIPv6(host) : host.split(':');
        for (let i = 0; i < 8; i++) {
            addr.writeUInt16BE(parseInt(parts[i], 16), i * 2);
        }
        return Buffer.concat([portBuf, Buffer.from([0x03]), addr]);
    }

    const domain = Buffer.from(host);
    return Buffer.concat([portBuf, Buffer.from([0x02, domain.length]), domain]);
}

function expandIPv6(host) {
    const [head, tail] = host.split('::');
    const headParts = head ? head.split(':') : [];
    const tailParts = tail ? tail.split(':') : [];
    const missing = 8 - headParts.length - tailParts.length;
    return [...headParts, ...Array(missing).fill('0'), ...tailParts];
}

function createUdpSocket(host) {
    const ip = net.isIP(host);
    return dgram.createSocket(ip === 6 ? 'udp6' : 'udp4');
}

function bindRelayCleanup(duplex, local, onClose) {
    let closed = false;
    const cleanup = () => {
        if (closed) {
            return;
        }
        closed = true;
        if (typeof local.destroy === 'function') {
            local.destroy();
        } else {
            local.close();
        }
        duplex.destroy();
        onClose();
    };
    duplex.on('error', cleanup);
    duplex.on('close', cleanup);
    local.on('error', () => {});
    local.on('close', cleanup);
}

function relayTcp(duplex, host, port, initial, onClose) {
    const socket = net.connect({host, port}, () => {
        if (initial.length) {
            socket.write(initial);
        }
        duplex.pipe(socket).pipe(duplex);
    });
    bindRelayCleanup(duplex, socket, onClose);
}

function writeLengthPacket(duplex, payload) {
    const header = Buffer.alloc(2);
    header.writeUInt16BE(payload.length, 0);
    duplex.write(Buffer.concat([header, payload]));
}

/** VLESS UDP (command 0x02): [2B length BE][payload] */
function relayUdp(duplex, host, port, initial, onClose) {
    const socket = createUdpSocket(host);
    let pending = initial;

    socket.on('error', () => {});

    const flushLengthPackets = () => {
        while (pending.length >= 2) {
            const len = pending.readUInt16BE(0);
            if (pending.length < 2 + len) {
                return;
            }
            const payload = pending.subarray(2, 2 + len);
            pending = pending.subarray(2 + len);
            socket.send(payload, port, host, () => {});
        }
    };

    socket.on('message', (msg) => {
        writeLengthPacket(duplex, msg);
    });

    duplex.on('data', chunk => {
        pending = pending.length ? Buffer.concat([pending, chunk]) : chunk;
        flushLengthPackets();
    });

    bindRelayCleanup(duplex, socket, () => {
        onClose();
    });
    flushLengthPackets();
}

/**
 * Parse XUDP meta (inside a Mux frame). See Xray common/xudp/xudp.go PacketReader.
 * @returns {{host?:string, port?:number, discard:boolean}|null}
 */
function parseXudpMeta(meta) {
    if (meta.length < 4) {
        return null;
    }

    const status = meta[2];
    const option = meta[3];

    if (option !== 0x01) {
        return null;
    }
    if (status === 0x04) {
        return {discard: true};
    }

    let host;
    let port;
    const hasUdpDest = meta.length > 4 && meta[4] === 0x02 && (status === 0x01 || status === 0x02);
    if (hasUdpDest) {
        try {
            let offset = 5;
            ({host, port, offset} = readPortThenAddress(meta, offset));
            if (status === 0x01 && meta.length - offset >= 8) {
                offset += 8;
            }
        } catch (err) {
            return null;
        }
    }

    return {host, port, discard: false};
}

/**
 * Server→client XUDP frames must use status Keep (0x02) with per-packet UDP address.
 * Clients reject status New (0x01) on the download path (sing-vmess: "unexpected frame new").
 */
function writeXudpPacket(duplex, host, port, payload) {
    const addr = encodePortThenAddress(host, port);
    const metaPayload = Buffer.concat([Buffer.from([0, 0, 0x02, 0x01, 0x02]), addr]);
    const metaLenBuf = Buffer.alloc(2);
    metaLenBuf.writeUInt16BE(metaPayload.length, 0);
    const dataLenBuf = Buffer.alloc(2);
    dataLenBuf.writeUInt16BE(payload.length, 0);
    const frame = Buffer.concat([metaLenBuf, metaPayload, dataLenBuf, payload]);
    duplex.write(frame);
}

/**
 * Detect XUDP inside a Mux body (inverse of Xray isMuxAndNotXUDP).
 * @param {Buffer} buf Body bytes after the VLESS handshake
 * @returns {boolean|null} true if XUDP, false if plain Mux, null if fewer than 7 bytes
 */
function isXudpMuxBody(buf) {
    if (buf.length < 7) {
        return null;
    }
    return buf[2] === 0 && buf[3] === 0 && buf[6] === 0x02;
}

/** VLESS XUDP (command 0x03 Mux + XUDP body framing) */
function relayXudp(duplex, initial, onClose) {
    const socket = dgram.createSocket('udp4');
    let pending = initial;
    let cursor = 0;
    let xudpValidated = false;
    let rejected = false;

    const reject = () => {
        if (rejected) {
            return;
        }
        rejected = true;
        socket.close();
        duplex.destroy();
        onClose();
    };

    const ensureXudp = () => {
        if (rejected) {
            return false;
        }
        if (xudpValidated) {
            return true;
        }
        const isXudp = isXudpMuxBody(pending);
        if (isXudp === null) {
            return true;
        }
        if (!isXudp) {
            reject();
            return false;
        }
        xudpValidated = true;
        return true;
    };

    socket.on('error', () => {});

    const processFrames = () => {
        if (!ensureXudp() || !xudpValidated) {
            return;
        }
        while (cursor + 2 <= pending.length) {
            const metaLen = pending.readUInt16BE(cursor);
            if (cursor + 2 + metaLen > pending.length) {
                break;
            }
            const meta = pending.subarray(cursor + 2, cursor + 2 + metaLen);
            const dataLenOffset = cursor + 2 + metaLen;
            if (dataLenOffset + 2 > pending.length) {
                break;
            }
            const dataLen = pending.readUInt16BE(dataLenOffset);
            if (dataLenOffset + 2 + dataLen > pending.length) {
                break;
            }
            const payload = pending.subarray(dataLenOffset + 2, dataLenOffset + 2 + dataLen);
            cursor = dataLenOffset + 2 + dataLen;

            const parsed = parseXudpMeta(meta);
            if (!parsed || parsed.discard) {
                continue;
            }
            if (!parsed.host) {
                continue;
            }

            socket.send(payload, parsed.port, parsed.host, () => {});
        }
        if (cursor > 0) {
            pending = pending.subarray(cursor);
            cursor = 0;
        }
    };

    socket.on('message', (msg, rinfo) => {
        writeXudpPacket(duplex, rinfo.address, rinfo.port, msg);
    });

    duplex.on('data', chunk => {
        if (rejected) {
            return;
        }
        pending = pending.length ? Buffer.concat([pending, chunk]) : chunk;
        processFrames();
    });

    bindRelayCleanup(duplex, socket, () => {
        if (!rejected) {
            onClose();
        }
    });
    processFrames();
}

function relayTraffic(duplex, handshake, initial, onClose) {
    const {command, host, port} = handshake;
    if (command === CMD_UDP) {
        relayUdp(duplex, host, port, initial, onClose);
        return;
    }
    if (command === CMD_MUX) {
        relayXudp(duplex, initial, onClose);
        return;
    }
    if (command === CMD_TCP) {
        relayTcp(duplex, host, port, initial, onClose);
        return;
    }
    duplex.destroy();
    onClose();
}

module.exports = {
    CMD_TCP,
    CMD_UDP,
    CMD_MUX,
    parseHandshake,
    relayTraffic,
};
