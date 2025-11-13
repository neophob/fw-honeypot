import { generateKeyPairSync } from "crypto";
import ssh2 from "ssh2";
import { AbstractHoneypotIntegration } from "./AbstractHoneypotIntegration.js";
import { splitIpAddress } from "../utils/ip-utils.js";
import { HoneypotServer } from "../CreateHoneypot.js";
import { mergeConfigs } from "../utils/config-utils.js";
import { stats } from "../utils/statistics.js";
import { track } from "../utils/tracker.js";

import { handleServerAuth } from "./ssh/server-auth.js";
import { handleClientSessionSession, handleExec } from "./ssh/client-session.js";

import debug from "debug";

const { Server } = ssh2;
const SERVICE_NAME = "SSH";
const debugLog = debug(SERVICE_NAME);

const { privateKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  privateKeyEncoding: {
    type: "pkcs1",
    format: "pem",
  },
  publicKeyEncoding: {
    type: "spki",
    format: "pem",
  },
});

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
    this.serverConfig = {
      hostKeys: [privateKey],
    };
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

    const server = new Server(this.serverConfig, (client, info) => {
      const ip = splitIpAddress(client._sock.remoteAddress);
      let authAttempts = 0;
      const sessionInfo = [];
      debugLog("Client authenticated (ready): %O", ip);
      sessionInfo.push(`Client:${JSON.stringify(info.header)}`);
      stats.increaseCounter("SSH_CONNECTION");
      stats.increaseCounter("CONNECTION");

      client
        .on("authentication", (ctx) => {
          authAttempts += 1;
          handleServerAuth(ctx, ip, authAttempts);
        })
        .on("ready", () => {
          debugLog("Client authenticated (ready) %s:", ip);

          client.on("session", (accept, reject) => {
            const session = accept();

            session.on("pty", (acceptPty, rejectPty, info) => {
              debugLog(
                `PTY requested from ${ip} info=${JSON.stringify(info)}`,
              );
              sessionInfo.push(`PTY:${JSON.stringify(info)}`);
              acceptPty && acceptPty();
            });

            session.on("window-change", (acceptW, reject, info) => {
              debugLog(
                `Window-Change requested from ${ip} info=${JSON.stringify(info)}`,
              );
              sessionInfo.push(`Window Change:${JSON.stringify(info)}`);
              acceptW && acceptW();
            });

            session.on("env", (acceptE, reject, info) => {
              debugLog(
                `env requested from ${ip} info=${JSON.stringify(info)}`,
              );
              sessionInfo.push(`ENV:${info.key}=${info.val}`);
              acceptE && acceptE();
            });

            session.on("shell", (acceptShell) => {
              const hexData = Buffer.from(
                sessionInfo.join(", "),
                "utf8",
              ).toString("hex");
              track(ip, SERVICE_NAME, hexData);
              handleClientSessionSession(acceptShell, ip);
            });

            session.on("exec", (acceptExec, rejectExec, info) => {
              stats.increaseCounter("SSH_EXEC");
              const stream = acceptExec();
              debugLog(
                `Exec request from ${ip} command=${info.command}`,
              );
              // Emulate execution with canned outputs, delay to look realistic
              track(ip, SERVICE_NAME, Buffer.from('"' + info.command + '", ', "utf8").toString("hex"));
              handleExec(info.command, stream, ip);
            });

            session.on("sftp", (acceptSftp, rejectSftp) => {
              stats.increaseCounter("SSH_SFTP");
              debugLog(
                `SFTP request from ${ip} - rejecting (not implemented)`,
              );
              // reject to appear like server without SFTP or limited SFTP
              rejectSftp && rejectSftp();
            });
          });
        })
        .on("close", () => {
          debugLog("Client disconnected");
        })
        .on("end", () => {
          debugLog("Client end");
        })
        .on("error", (err) => {
          debugLog("ERROR: " + err.message);
          stats.increaseCounter("SSH_ERROR");
          stats.addErrorMessage(`SSH_SERVER_ERROR#${err.message}`);
        });
    });
    this.#server = server;
  }

  listen() {
    this.#server
      .listen(this.#config.port, () => {
        debugLog(
          `[SSH] Honeypot is listening on port ${this.#config.host}:${this.#config.port}`,
        );
      })
      .on("error", (err) => {
        debugLog(`Error: ${err.message}`);
        stats.increaseCounter("SSH_ERROR");
        stats.addErrorMessage(`SSH_SERVER_ERROR#${err.message}`);
      });
  }
}
