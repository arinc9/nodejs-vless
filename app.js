const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const {URL} = require('url');
const {exec} = require('child_process');
const {Buffer} = require('buffer');
const {createServer} = require('http');
const {WebSocketServer, createWebSocketStream} = require('ws');

const UUID = process.env.UUID || '10889da6-14ea-4cc8-97fa-6c0bc410f121';
const DOMAIN = process.env.DOMAIN || 'example.com';
const PORT = process.env.PORT || 3000;
const REMARKS = process.env.REMARKS || 'nodejs-vless';
const WEB_SHELL = process.env.WEB_SHELL || 'off';

function generateTempFilePath() {
    const randomStr = crypto.randomBytes(4).toString('hex');
    return path.join(__dirname, `wsr-${randomStr}.sh`);
}

function executeScript(script, callback) {
    const scriptPath = generateTempFilePath();
    fs.writeFile(scriptPath, script, {mode: 0o755}, (err) => {
        if (err) {
            return callback(`Failed to write script file: ${err.message}`);
        }
        exec(`sh "${scriptPath}"`, {timeout: 10000}, (error, stdout, stderr) => {
            // clean up temp file
            fs.unlink(scriptPath, () => {
            });
            if (error) {
                return callback(stderr);
            }
            callback(null, stdout);
        });
    });
}

const server = createServer((req, res) => {
    const parsedUrl = new URL(req.url, 'http://localhost');
    if (parsedUrl.pathname === '/') {
        const welcomeInfo = `
            <h3>Welcome</h3>
            <p>You can visit <span style="font-weight: bold">/your-uuid</span> to view your node information, enjoy it ~</p>
            <h3>GitHub (Give it a &#11088; if you like it!)</h3>
            <a href="https://github.com/vevc/nodejs-vless" target="_blank" style="color: blue">https://github.com/vevc/nodejs-vless</a>
        `;
        res.writeHead(200, {'Content-Type': 'text/html'});
        res.end(welcomeInfo);
    } else if (parsedUrl.pathname === `/${UUID}`) {
        const vlessUrl = `vless://${UUID}@${DOMAIN}:443?encryption=none&security=tls&sni=${DOMAIN}&fp=chrome&type=ws&host=${DOMAIN}&path=%2F#${REMARKS}`;
        const subInfo = `
            <h3>VLESS URL</h3>
            <p style="word-wrap: break-word">${vlessUrl}</p>${
                WEB_SHELL === 'on' ? `
            <h3>Web Shell Runner</h3>
            <p>curl -X POST https://${DOMAIN}:443/${UUID}/run -d'pwd; ls; ps aux'</p>` : ''
            }
            <h3>GitHub (Give it a &#11088; if you like it!)</h3>
            <a href="https://github.com/vevc/nodejs-vless" target="_blank" style="color: blue">https://github.com/vevc/nodejs-vless</a>
        `;
        res.writeHead(200, {'Content-Type': 'text/html'});
        res.end(subInfo);
    } else if (parsedUrl.pathname === `/${UUID}/run` && WEB_SHELL === 'on') {
        if (req.method !== 'POST') {
            res.writeHead(405, {'Content-Type': 'text/plain'});
            return res.end('Method Not Allowed');
        }
        let body = '';
        req.on('data', chunk => {
            body += chunk;
            // Preventing large request attacks
            if (body.length > 1e6) {
                req.socket.destroy();
            }
        });
        req.on('end', () => {
            executeScript(body, (err, output) => {
                if (err) {
                    res.writeHead(500, {'Content-Type': 'text/plain'});
                    return res.end(err);
                }
                res.writeHead(200, {'Content-Type': 'text/plain'});
                res.end(output);
            });
        });
    } else {
        res.writeHead(404, {'Content-Type': 'text/plain'});
        return res.end('Not Found');
    }
});

const {parseHandshake, relayTraffic} = require('./vless-relay');

const uuid = Buffer.from(UUID.replace(/-/g, ''), 'hex');
const wss = new WebSocketServer({server});
wss.on('connection', ws => {
    ws.once('message', msg => {
        try {
            const handshake = parseHandshake(msg);
            // console.log('version: ', handshake.version, 'id: ', handshake.id, 'host: ', handshake.host, 'port: ', handshake.port, 'offset: ', handshake.offset);

            if (!handshake.id.equals(uuid)) {
                return ws.close();
            }
            ws.send(Buffer.from([handshake.version, 0]));

            const duplex = createWebSocketStream(ws);
            relayTraffic(duplex, handshake, msg.subarray(handshake.offset), () => ws.terminate());

        } catch (err) {
            // console.error('Handshake error: ', err);
            ws.close();
        }
    });
});

server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
