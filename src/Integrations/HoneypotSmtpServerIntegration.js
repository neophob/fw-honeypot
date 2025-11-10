import { AbstractHoneypotIntegration } from "./AbstractHoneypotIntegration.js";
import { HoneypotServer } from "../CreateHoneypot.js";
import { mergeConfigs } from "../utils/config-utils.js";
import { SMTPServer } from "smtp-server";
import { splitIpAddress } from "../utils/ip-utils.js";
import { stats } from "../utils/statistics.js";
import { track } from "../utils/tracker.js";
import debug from "debug";

const SERVICE_NAME = "SMTP";
const debugLog = debug(SERVICE_NAME);

export class HoneypotSmtpServerIntegration extends AbstractHoneypotIntegration {
  #server;

  /**
   * @type {HoneypotServerConfig}
   */
  #config = {
    port: 25,
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

    const server = new SMTPServer({
      name: "mail.local",
      banner: "welcome",
      logger: false,
      disabledCommands: ["AUTH"],

      onData(stream, session, callback) {
        let data = "";
        stats.increaseCounter("SMTP_DATA");

        stream.on("data", (chunk) => {
          data += chunk.toString();
        });

        stream.on("end", () => {
          track(ip, SERVICE_NAME, data.toString());
          debugLog(data.toString());
          callback();
        });

        // Resume the stream if paused
        stream.resume();
      },

      onRcptTo(address, session, callback) {
        debugLog(`Recipient: ${address.address}`);
        stats.increaseCounter("SMTP_TO");
        return callback();
      },

      onMailFrom(address, session, callback) {
        debugLog(`Mail from: ${address.address}`);
        stats.increaseCounter("SMTP_FROM");
        return callback();
      },

      onConnect(session, callback) {
        const ip = splitIpAddress(session.remoteAddress);
        debugLog(`Connection attempt from ${ip} - ${session.clientHostname}`);
        //honeypotServer.attacker.add(ip, config.banDurationMs);
        stats.increaseCounter("SMTP_CONNECTION");
        callback();
      },
    });

    this.#server = server;
  }

  listen() {
    this.#server.listen(this.#config.port, this.#config.host, () => {
      debugLog(
        `[SMTP] Honeypot is listening on port ${this.#config.host}:${this.#config.port}`,
      );
    });
  }
}
