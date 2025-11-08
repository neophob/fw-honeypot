import { AbstractHoneypotIntegration } from "./AbstractHoneypotIntegration.js";
import net from "net";
import { splitIpAddress } from "../utils/ip-utils.js";
import { HoneypotServer } from "../CreateHoneypot.js";
import { mergeConfigs } from "../utils/config-utils.js";
import { stats } from "../utils/statistics.js";
import debug from "debug";
const debugLog = debug("Telnet");

const TELNET_BANNER = "Welcome to Telnet Honeypot\r\n";

export class HoneypotTelnetServerIntegration extends AbstractHoneypotIntegration {
  #server;

  /**
   * @type {HoneypotServerConfig}
   */
  #config = {
    port: 23,
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
    /**
     * @type {HoneypotServerConfig}
     */
    const config = mergeConfigs(honeypotServer.config, this.config);
    this.config = config;
    debugLog("Config: <%o>", this.config);

    const server = net.createServer((socket) => {
      const ip = splitIpAddress(socket.remoteAddress);

      debugLog(`New connection from %o`, socket.address());
      stats.increaseCounter("TELNET_CONNECTION");

      if (!ip) {
        debugLog(`Invalid IP address <${socket.remoteAddress}>. Connection closed.`);
        stats.increaseCounter("TELNET_INVALID_IP");
        socket.destroy();
        return;
      }

      socket.on("error", (err) => {
        stats.increaseCounter("TELNET_ERROR");
        debugLog(`Socket error from ${ip}: ${err.message}`);
      });

      honeypotServer.attacker.add(ip, config.banDurationMs);

      socket.write(TELNET_BANNER);
      socket.write("login: ");

      socket.on("data", (data) => {
        stats.increaseCounter("TELNET_DATA");
        const input = data.toString().trim();
        debugLog(`Input from ${ip}: ${input}`);
        socket.write("Invalid login.\r\nlogin: ");
      });

      setTimeout(() => {
        socket.destroy();
        debugLog(`Connection from ${ip} has been closed.`);
      }, 10000);
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
      });
  }
}
