import { AbstractHoneypotIntegration } from "./AbstractHoneypotIntegration.js";
import { HoneypotServer } from "../CreateHoneypot.js";
import { mergeConfigs } from "../utils/config-utils.js";
import debug from "debug";
const debugLog = debug("HoneypotSMBServerIntegration");
import net from "net";

const SMB_BANNER = Buffer.from([
  0xff,
  0x53,
  0x4d,
  0x42, // "SMB" Header
  0x72, // Command (Negotiate Protocol)
]);

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

      debugLog(`New connection from %o`, socket.address());

      if (!ip) {
        debugLog("Invalid IP address. Connection closed.");
        socket.destroy();
        return;
      }

      socket.on("error", (err) => {
        debugLog(`Socket error from ${ip}: ${err.message}`);
      });

      honeypotServer.attacker.add(ip, config.banDurationMs);

      // Simuliere SMB-Protokoll
      socket.write(SMB_BANNER);

      socket.on("data", (data) => {
        debugLog(`Data from ${ip}: ${data.toString("hex")}`);
      });

      // Verbindung nach 10 Sekunden beenden
      setTimeout(() => {
        socket.destroy();
        debugLog(`Connection from ${ip} has been closed.`);
      }, 10000);
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
      });
  }
}
