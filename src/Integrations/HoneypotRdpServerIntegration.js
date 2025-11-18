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
                stats.increaseCounter("RDP_DATA");
                debugLog(`Data ${ip}: ${data.toString("hex")}`);
                // Track each data chunk directly
                track(ip, SERVICE_NAME, data.toString("hex"));


                // Basic RDP Handshake handling
                // Check for X.224 Connection Request (CR)
                // First byte is length, second byte is 0xE0 (CR)
                if (data.length >= 4 && data[1] === 0xe0) {
                    debugLog(`Received X.224 Connection Request from ${ip}`);

                    // Construct X.224 Connection Confirm (CC)
                    // LI (Length) = 4
                    // Code = 0xD0 (CC)
                    // DST-REF = 0x0000 (using 0 for simplicity)
                    // SRC-REF = 0x1234 (arbitrary)
                    // Class = 0x00

                    // A simple valid CC packet: 03 D0 00 00 12 34 00 ... wait, let's look at a real trace or spec.
                    // Actually, a minimal CC is:
                    // LI (1 byte), Code (1 byte), DST-REF (2 bytes), SRC-REF (2 bytes), Class (1 byte)
                    // Total 7 bytes?
                    // Let's try a standard response seen in other honeypots like Cowrie or similar for RDP.
                    // 0x04 (Length 4 bytes excluding LI?) No, LI includes header excluding itself usually? 
                    // RFC 1006 / TPKT might be wrapping it if it's over TCP port 3389 directly? 
                    // RDP usually uses TPKT (RFC 1006) header first: Version (1), Reserved (1), Length (2).

                    // Let's check if the incoming data has TPKT header.
                    // TPKT: v=3, r=0, len=...

                    if (data[0] === 0x03 && data[1] === 0x00) {
                        // It's likely TPKT.
                        // Let's just send back a canned TPKT + X.224 CC response.
                        // TPKT Header: 03 00 00 0B (11 bytes total)
                        // X.224 CC: 06 (LI) D0 (CC) 00 00 (DST) 12 34 (SRC) 00 (Class)

                        const response = Buffer.from([
                            0x03, 0x00, 0x00, 0x0b, // TPKT Header (length 11)
                            0x06, // X.224 LI
                            0xd0, // X.224 CC
                            0x00, 0x00, // DST-REF
                            0x12, 0x34, // SRC-REF
                            0x00 // Class 0
                        ]);
                        socket.write(response);
                        debugLog(`Sent X.224 Connection Confirm to ${ip}`);
                    }
                }
            });

            socket.on('end', () => {
                debugLog(`Connection from ${ip} has been closed (client ended).`);
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
