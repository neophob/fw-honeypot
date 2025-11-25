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

                    debugLog(`RDP_INITIAL_HANDSHAKE_DONE ${ip}`);
                    // CR packet handled - wait for next packet (Security Exchange or Client Info)
                    return;
                }

                // For non-CR packets: TPKT(4) + X.224 Data TPDU(3) = offset 7
                // X.224 Data TPDU is: LI(1) + Code(1) + EOT(1) = 3 bytes typically
                // But in practice, RDP uses a simplified format where byte 4 is just 0x02
                if (data.length < 7) {
                    debugLog(`Packet too small for RDP parsing: ${data.toString("hex")}`);
                    return;
                }

                // After TPKT (4 bytes), check X.224 Data TPDU marker (0x02)
                // Then the RDP PDU type is in the MCS layer
                // For simplicity, we look at specific byte patterns
                const byte4 = data[4];
                const byte5 = data[5];

                debugLog(`Packet structure - byte4: ${byte4.toString(16)}, byte5: ${byte5.toString(16)}`);

                // Detect Security Exchange (look for MCS pattern)
                const isSecurityExchange = byte4 === 0x02 && byte5 === 0xf0;
                // Detect Client Info (look for different MCS pattern or specific identifier)
                const isClientInfo = byte4 === 0x02 && data.length > 10;
                // Check for Security Exchange pattern
                if (isSecurityExchange && data.length > 15) {
                    debugLog(`Detected Security Exchange from ${ip}`);
                    // Track the encrypted credential blob
                    track(ip, `${SERVICE_NAME}_CRED`, chunkHex);
                    stats.increaseCounter("RDP_SECURITY_EXCHANGE");
                    return;
                }
                // Check for Client Info pattern
                if (isClientInfo && !isSecurityExchange) {
                    debugLog(`Attempting to parse Client Info from ${ip}`);
                    // Try to extract username - look for domain/username fields
                    // Client Info structure varies, but typically starts around offset 10-15
                    try {
                        let offset = 10;
                        if (data.length >= offset + 2) {
                            const domainLen = data.readUInt16LE(offset) * 2;
                            debugLog(`Domain length: ${domainLen}`);
                            offset += 2;

                            if (data.length >= offset + domainLen + 2) {
                                offset += domainLen;
                                const userLen = data.readUInt16LE(offset) * 2;
                                debugLog(`Username length: ${userLen}`);
                                offset += 2;

                                if (data.length >= offset + userLen && userLen > 0 && userLen < 512) {
                                    const usernameBuf = data.slice(offset, offset + userLen);
                                    const username = usernameBuf.toString('utf16le').replace(/\0+$/g, '');
                                    debugLog(`RDP Username extracted from ${ip}: "${username}"`);
                                    track(ip, `${SERVICE_NAME}_USERNAME`, Buffer.from(username, "utf8").toString("hex"));
                                    track(ip, `${SERVICE_NAME}_CLIENTINFO`, chunkHex);
                                } else {
                                    debugLog(`Invalid username length or incomplete data: ${userLen}`);
                                    track(ip, `${SERVICE_NAME}_CLIENTINFO_RAW`, chunkHex);
                                }
                            }
                        }
                    } catch (err) {
                        debugLog(`Error parsing Client Info from ${ip}: ${err.message}`);
                        track(ip, `${SERVICE_NAME}_CLIENTINFO_RAW`, chunkHex);
                    }
                    return;
                }
                // If we get here, it's an unknown packet type - just track it
                debugLog(`Unknown RDP packet type from ${ip}, tracking as raw data`);
                // Raw data already tracked at the top of the handler
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
