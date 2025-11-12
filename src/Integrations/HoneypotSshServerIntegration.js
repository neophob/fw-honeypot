import { generateKeyPairSync } from "crypto";
import ssh2 from "ssh2";
import { AbstractHoneypotIntegration } from "./AbstractHoneypotIntegration.js";
import { HoneypotServer } from "../CreateHoneypot.js";
import { mergeConfigs } from "../utils/config-utils.js";
import { stats } from "../utils/statistics.js";
import { track } from "../utils/tracker.js";

import { handleServerAuth } from "./ssh/server-auth.js";
import { handleClientSessionSession } from "./ssh/client-session.js";

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

    const server = new Server(this.serverConfig, (client) => {
      const clientAddr =
        client._sock.remoteAddress + ":" + client._sock.remotePort;
      let authAttempts = 0;

      client
        .on("authentication", (ctx) => {
          authAttempts += 1;
          const clientAddr =
            client._sock.remoteAddress + ":" + client._sock.remotePort;
          handleServerAuth(ctx, clientAddr, authAttempts);
        })
        .on("ready", () => {
          debugLog("Client authenticated (ready):", clientAddr);

          client.on("session", (accept, reject) => {
            const session = accept();

            session.on("pty", (acceptPty, rejectPty, info) => {
              debugLog(
                "PTY requested from",
                clientAddr,
                "info=",
                JSON.stringify(info),
              );
              acceptPty && acceptPty();
            });

            session.on("window-change", (acceptW, reject, info) => {
              debugLog(
                "Window-Change requested from",
                clientAddr,
                "info=",
                JSON.stringify(info),
              );
              acceptW && acceptW();
            });

            session.on("env", (acceptE, reject, info) => {
              debugLog(
                "env requested from",
                clientAddr,
                "info=",
                JSON.stringify(info),
              );
              acceptE && acceptE();
            });

            session.on("shell", (acceptShell) => {
              handleClientSessionSession(acceptShell, clientAddr);
            });

            session.on("exec", (acceptExec, rejectExec, info) => {
              const stream = acceptExec();
              debugLog(
                `Exec request from ${clientAddr} command=${info.command}`,
              );
              // Emulate execution with canned outputs, delay to look realistic
              emulateExec(info.command, stream, clientAddr);
            });

            session.on("sftp", (acceptSftp, rejectSftp) => {
              debugLog(
                `SFTP request from ${clientAddr} - rejecting (not implemented)`,
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
          stats.addErrorMessage("SSH_SERVER_ERROR#" + err.message);
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
        stats.addErrorMessage(`SSH_SERVER_ERROR#${err.message}`);
      });
  }
}

/*    const server = net.createServer((socket) => {
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
        track(ip, SERVICE_NAME, data.toString("hex"));
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
    });*/
