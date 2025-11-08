import { AbstractHoneypotIntegration } from "./AbstractHoneypotIntegration.js";
import net from "net";
import { splitIpAddress } from "../utils/ip-utils.js";
import { HoneypotServer } from "../CreateHoneypot.js";
import { mergeConfigs } from "../utils/config-utils.js";
import { stats } from "../utils/statistics.js";
import { track } from "../utils/tracker.js";
import debug from "debug";

const SSH_BANNER = "SSH-2.0-OpenSSH_8.6\r\n";
const SERVICE_NAME = "SSH";
const debugLog = debug(SERVICE_NAME);

export class HoneypotSshServerIntegration extends AbstractHoneypotIntegration {
  #server;

  /**
   * @type {HoneypotServerConfig}
   */
  #config = {
    port: 22,
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
   * @param {HoneypotServer} server
   */
  create(honeypotServer) {
    /**
     * @type {HoneypotServerConfig}
     */
    const config = mergeConfigs(honeypotServer.config, this.config);
    this.config = config;
    debugLog("Config: <%o>", this.config);

    const server = net.createServer((socket) => {
      let handshakeDone = false;
      const ip = splitIpAddress(socket.remoteAddress);

      debugLog(`New connection from %o`, socket.address());
      stats.increaseCounter("SSH_CONNECTION");

      if (!ip) {
        debugLog(
          `Invalid IP address <${socket.remoteAddress}>. Connection closed.`,
        );
        stats.increaseCounter("SSH_INVALID_IP");
        socket.destroy();
        return;
      }

      socket.on("error", (err) => {
        debugLog(`Socket error from ${ip}: ${err.message}`);
        stats.increaseCounter("SSH_ERROR");
      });

      //honeypotServer.attacker.add(ip, config.banDurationMs);
      socket.write(SSH_BANNER);

      socket.on("data", (data) => {
        debugLog(`Received data from ${ip}: ${data.toString()}`);
        track(ip, SERVICE_NAME, data.toString());
        stats.increaseCounter("SSH_DATA");

        if (!handshakeDone) {
          // Mock KEXINIT reply
          // type 20 = SSH_MSG_KEXINIT
          socket.write(
            Buffer.from([
              0x14, // SSH_MSG_KEXINIT
              ...Buffer.alloc(15, 0), // cookie (random bytes normally)
              0x00,
              0x00,
              0x00,
              0x00, // fake algorithm lists lengths
            ]),
          );

          // Mock NEWKEYS
          socket.write(Buffer.from([0x15])); // type 21 = SSH_MSG_NEWKEYS

          handshakeDone = true;
          console.log(`Mock handshake completed for ${ip}`);
          return;
        }
      });

      setTimeout(() => {
        socket.destroy();
        debugLog(`Connection from ${ip} has been closed.`);
      }, 5000);
    });

    this.#server = server;
  }

  listen() {
    this.#server
      .listen(this.#config.port, this.#config.host, () => {
        debugLog(
          `[SSH] Honeypot is listening on port ${this.#config.host}:${this.#config.port}`,
        );
      })
      .on("error", (err) => {
        debugLog(`Error: ${err.message}`);
      });
  }
}
