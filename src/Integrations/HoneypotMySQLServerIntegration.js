import { AbstractHoneypotIntegration } from "./AbstractHoneypotIntegration.js";
import net from "net";
import { splitIpAddress } from "../utils/ip-utils.js";
import { HoneypotServer } from "../CreateHoneypot.js";
import { mergeConfigs } from "../utils/config-utils.js";
import { stats } from "../utils/statistics.js";
import debug from "debug";
const debugLog = debug("MySQL");

const MYSQL_HANDSHAKE = Buffer.from([
  0x0a, // Protocol version
  ...Buffer.from("5.7.31-log"), // Server version
  0x00,
  0x00,
  0x00,
  0x00, // Connection ID
  0x08,
  0x00,
  0x00,
  0x00, // Capabilities flags
  0x21,
  0x00, // Charset (utf8_general_ci)
  0x02,
  0x00, // Status flags
]);

export class HoneypotMySQLServerIntegration extends AbstractHoneypotIntegration {
  #server;

  /**
   * @type {HoneypotServerConfig}
   */
  #config = {
    port: 3306,
  };

  constructor(config) {
    super();
    this.config = mergeConfigs(this.config, config);
    debugLog("Config: <%o>", this.config);
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

    this.#server = net.createServer((socket) => {
      const ip = splitIpAddress(socket.remoteAddress);
      debugLog(`New connection from %o`, socket.address());
      stats.increaseCounter("MYSQL_CONNECTION");

      if (!ip) {
        debugLog(`Invalid IP address <${socket.remoteAddress}>. Connection closed.`);
        stats.increaseCounter("MYSQL_INVALID_IP");
        socket.destroy();
        return;
      }

      socket.on("error", (err) => {
        stats.increaseCounter("MYSQL_ERROR");
        stats.addErrorMessage("MYSQL#" + err.message);
        debugLog(`Socket error from ${ip}: ${err.message}`);
      });

      honeypotServer.attacker.add(ip, config.banDurationMs);

      // Send handshake packet
      socket.write(MYSQL_HANDSHAKE);

      // Handle incoming packets
      socket.on("data", (data) => {
        debugLog(`Received data from ${ip}: ${data.toString("hex")}`);
        stats.increaseCounter("MYSQL_DATA");

        // Simulate a failed login
        const failurePacket = Buffer.from([
          0xff,
          0x15,
          0x04,
          0x23,
          ...Buffer.from("28000 Access denied for user"),
        ]);
        socket.write(failurePacket);
      });

      // Close connection after a timeout
      setTimeout(() => {
        socket.destroy();
        debugLog(`Connection from ${ip} has been closed.`);
      }, 5000);
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
