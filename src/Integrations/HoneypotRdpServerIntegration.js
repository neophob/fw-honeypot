import { AbstractHoneypotIntegration } from "./AbstractHoneypotIntegration.js";
import net from "net";
import { splitIpAddress } from "../utils/ip-utils.js";
import { HoneypotServer } from "../CreateHoneypot.js";
import { mergeConfigs } from "../utils/config-utils.js";
import { stats } from "../utils/statistics.js";
import { track } from "../utils/tracker.js";
import debug from "debug";

const SERVICE_NAME = "RDP";
const debugLog = debug(SERVICE_NAME);

// RDP Constants
const RDP_PORT = 3389;

export class HoneypotRdpServerIntegration extends AbstractHoneypotIntegration {
    #server;

    /**
     * @type {HoneypotServerConfig}
     */
    #config = {
        port: RDP_PORT,
    };

    constructor(config) {
        super();
        this.config = mergeConfigs(this.config, config);
    }

    /**
     * @return {HoneypotServerConfig}
     */
    get config() {
        return this.#config;
    }

    set config(config) {
        this.#config = config;
    }

    /**
     * @param {HoneypotServer} honeypotServer
     */
    create(honeypotServer) {
        const config = mergeConfigs(honeypotServer.config, this.config);
        this.config = config;
        debugLog("Config: <%o>", this.config);

        const server = net.createServer((socket) => {
            const ip = splitIpAddress(socket.remoteAddress);
            debugLog(`New connection from %o`, socket.address());
            stats.increaseCounter("RDP_CONNECTION");
            stats.increaseCounter("CONNECTION");

            if (!ip) {
                debugLog(
                    `Invalid IP address <${socket.remoteAddress}>. Connection closed.`,
                );
                stats.increaseCounter("RDP_INVALID_IP");
                stats.addErrorMessage(`RDP_INVALID_IP#${socket.remoteAddress}`);
                socket.destroy();
                return;
            }

            socket.on("error", (err) => {
                stats.increaseCounter("RDP_ERROR");
                stats.addErrorMessage(`RDP_SOCKET_ERROR#${err.message}`);
                debugLog(`Socket error from ${ip}: ${err.message}`);
            });


            socket.on("data", (data) => {
                // Increment data counter and log raw hex
                stats.increaseCounter("RDP_DATA");
                debugLog(`Data ${ip}: ${data.toString("hex")}`);
                // Track raw chunk
                const chunkHex = data.toString('hex');
                track(ip, SERVICE_NAME, chunkHex);

                // Detect X.224 Connection Request (CR) after TPKT header
                // The client sends a TPKT header (4 bytes) followed by X.224 CR (0x0e 0xe0 ...)
                // We'll respond with a Connection Confirm (CC) and then a Server Security Response
                if (data.length >= 6 && data[4] === 0x0e && data[5] === 0xe0) {
                    // Connection Confirm (11 bytes)
                    const cc = Buffer.from([
                        0x03, 0x00, 0x00, 0x0b, // TPKT Header (length 11)
                        0x06, // X.224 LI
                        0xd0, // X.224 CC
                        0x00, 0x00, // DST-REF
                        0x12, 0x34, // SRC-REF
                        0x00 // Class 0
                    ]);
                    socket.write(cc);
                    debugLog(`Sent X.224 Connection Confirm to ${ip}`);

                    // Check for embedded RDP Negotiation Request (0x01) immediately following X.224 CR
                    // This happens when the client sends both in one packet.
                    // The RDP Negotiation Request starts after TPKT (4 bytes) + X.224 CR (3 bytes)
                    // So, if data[7] is 0x01, it's an embedded negotiation request.
                    if (data.length >= 8 && data[7] === 0x01) {
                        debugLog(`Detected embedded RDP Negotiation Request from ${ip}`);
                        // Respond with Standard RDP Security (0x00000001)
                        const negotiationResponse = Buffer.from([
                            0x03, 0x00, 0x00, 0x0C, // TPKT header (len 12)
                            0x02, 0xF0, 0x80, 0x7F, // X.224 Data TPDU
                            0x00, 0x00, 0x00, 0x01 // Negotiation Response: selectedProtocol = 0x00000001
                        ]);
                        socket.write(negotiationResponse);
                        debugLog(`Sent RDP Negotiation Response (Standard RDP Security) to ${ip}`);
                    }

                    // Server Security Response (12 bytes)
                    const serverSecResp = Buffer.from([
                        0x03, 0x00, 0x00, 0x0c, // TPKT Header (len 12)
                        0x02, // X.224 Data TPDU
                        0x02, // Server Security Response code
                        // 8 zero bytes payload (server random, etc.)
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                    ]);
                    socket.write(serverSecResp);
                    debugLog(`RDP_INITIAL_HANDSHAKE_DONE ${ip}`);
                    return; // stop further processing of this packet
                }

                // Basic RDP packet parsing (skip TPKT header 4 bytes, X.224 header 1 byte)
                if (data.length < 6) {
                    debugLog(`too less RDP Data ${ip}: ${data.toString("hex")}`);
                    return;
                }
                const rdpType = data[5]; // after TPKT(4) + X.224(1)
                debugLog(`RDP Type extracted from ${ip}: ${rdpType}`);
                // 0x01 = Negotiation Request, 0x03 = Security Exchange, 0x04 = Client Info
                if (rdpType === 0x01) {
                    // Negotiation Request -> respond with Standard RDP Security (0x00000001)
                    const response = Buffer.from([
                        0x03, 0x00, 0x00, 0x0C, // TPKT header (len 12)
                        0x02, 0xF0, 0x80, 0x7F, // X.224 Data TPDU
                        0x00, 0x00, 0x00, 0x01 // Negotiation Response: selectedProtocol = 0x00000001
                    ]);
                    socket.write(response);
                    debugLog(`Sent RDP Negotiation Response (Standard RDP Security) to ${ip}`);
                    return;
                }
                if (rdpType === 0x03) {
                    // Security Exchange – client sent credentials, we acknowledge with a dummy Server Security Response
                    const serverSecResp = Buffer.from([
                        0x03, 0x00, 0x00, 0x0c, // TPKT Header (len 12)
                        0x02, // X.224 Data TPDU
                        0x02, // Server Security Response code
                        // Minimal payload (e.g., 8 zero bytes for server random & other fields)
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                    ]);
                    socket.write(serverSecResp);
                    debugLog(`Sent Server Security Response to ${ip}`);
                    stats.addErrorMessage(`RDP_SECURITY_RESPONSE_SENT#${ip}`);
                    return;
                }
                if (rdpType === 0x04) {
                    // Client Info – extract Unicode username
                    let offset = 10; // start after TPKT(4)+X.224(1)+RDP Header(1)+flags(2)+lengths(2)
                    if (data.length < offset + 2) {
                        debugLog(`RDP Client Info from ${ip}: ${data.toString("hex")}`);
                        return;
                    }
                    // Domain length (2 bytes)
                    const domainLen = data.readUInt16LE(offset) * 2;
                    offset += 2;
                    if (data.length < offset + domainLen) {
                        debugLog(`RDP Client Info incomplete domain data from ${ip}`);
                        return;
                    }
                    offset += domainLen; // skip domain string
                    // Username length (2 bytes)
                    if (data.length < offset + 2) {
                        debugLog(`RDP Client Info incomplete username length from ${ip}`);
                        return;
                    }
                    const userLen = data.readUInt16LE(offset) * 2;
                    debugLog(`RDP Username length bytes: ${userLen}`);
                    offset += 2;
                    if (data.length < offset + userLen) {
                        debugLog(`RDP Client Info incomplete username data from ${ip}`);
                        return;
                    }
                    const usernameBuf = data.slice(offset, offset + userLen);
                    const username = usernameBuf.toString('utf16le').replace(/\0+$/g, '');
                    debugLog(`RDP Username extracted from ${ip}: ${username}`);
                    track(ip, `${SERVICE_NAME}_USERNAME`, Buffer.from(username, "utf8").toString("hex"));
                    return;
                }
                // Other packet types are already tracked above.
            });

            socket.on('end', () => {
                debugLog(`Connection from ${ip} has been closed (client ended).`);
                // Ensure any remaining buffered data is flushed (if any)
                // No additional action needed because we track per packet.
            });
        });

        this.#server = server;
    }

    listen() {
        this.#server
            .listen(this.#config.port, this.#config.host, () => {
                debugLog(
                    `Honeypot is listening on port ${this.#config.host}:${this.#config.port}`,
                );
            })
            .on("error", (err) => {
                debugLog(`Error: ${err.message}`);
                stats.addErrorMessage(`RDP_SERVER_ERROR#${err.message}`);
            });
    }
}
