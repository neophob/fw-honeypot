import net from "net";
import { AbstractHoneypotIntegration } from "./AbstractHoneypotIntegration.js";
import { HoneypotServer } from "../CreateHoneypot.js";
import { mergeConfigs } from "../utils/config-utils.js";
import { stats } from "../utils/statistics.js";
import { track } from "../utils/tracker.js";
import { RateLimiter } from "../utils/rate-limiter.js";

import { handleSmbPacket } from "./smb/parser.js";
import debug from "debug";

const SERVICE_NAME = "SMB";
const debugLog = debug(SERVICE_NAME);
const rateLimiter = new RateLimiter();

export class HoneypotSMBServerIntegration extends AbstractHoneypotIntegration {
  #server;

  /**
   * @type {HoneypotServerConfig}
   */
  #config = {
    port: 445,
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

    this.#server = net.createServer((socket) => {
      const ip = socket.remoteAddress;
      const isHostBlocked = rateLimiter.checkIfBlocked(ip);

      if (isHostBlocked) {
        stats.increaseCounter("SMB_CONNECTION_BLOCKED");
        socket.destroy();
        return;
      } else {
        debugLog(`New connection from %o`, socket.address());
        stats.increaseCounter("SMB_CONNECTION_ACCEPTED");
      }

      stats.increaseCounter("CONNECTION");

      if (!ip) {
        debugLog(
          `Invalid IP address <${socket.remoteAddress}>. Connection closed.`,
        );
        stats.increaseCounter("SMB_INVALID_IP");
        socket.destroy();
        return;
      }

      socket.on("error", (err) => {
        stats.increaseCounter("SMB_ERROR");
        stats.addErrorMessage("SMB#" + err.message);
        debugLog(`Socket error from ${ip}: ${err.message}`);
      });

      //honeypotServer.attacker.add(ip, config.banDurationMs);

      // Buffer incoming data until we can process a full NetBIOS packet
      let recvBuf = Buffer.alloc(0);

      socket.on("data", (data) => {
        recvBuf = Buffer.concat([recvBuf, data]);
        stats.increaseCounter("SMB_DATA");
        track(ip, SERVICE_NAME, data.toString("hex"));

        // NetBIOS Session Service header is 4 bytes: [0] = 0x00, [1..3] length (big-endian)
        while (recvBuf.length >= 4) {
          // Read length from bytes 1..3
          const nbLen = recvBuf.readUIntBE(1, 3); // length of SMB payload
          if (recvBuf.length < 4 + nbLen) {
            // wait for full packet
            break;
          }

          // Extract full SMB packet (without NetBIOS header)
          const smbPacket = recvBuf.slice(4, 4 + nbLen);
          handleSmbPacket(socket, ip, smbPacket);

          // Remove processed packet
          recvBuf = recvBuf.slice(4 + nbLen);
        }
      });

      // close after some idle timeout
      const idleTimer = setTimeout(() => {
        socket.destroy();
        debugLog(`Connection from ${ip} has been closed (idle).`);
      }, 32000);

      socket.on("close", () => {
        debugLog(`Connection from ${ip} has been closed (active).`);
        clearTimeout(idleTimer);
      });
    });
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
        stats.addErrorMessage(`SMB_SERVER_ERROR#${err.message}`);
      });
  }
}
