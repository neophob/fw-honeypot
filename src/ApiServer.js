import http from "http";
import debug from "debug";
const debugLog = debug("ApiServer");
import { mergeCidr } from "cidr-tools";

export class ApiServer {
  /**
   * @type {http.Server}
   */
  #server;

  /**
   * @type {HoneypotServer}
   */
  #honeypotServer;

  constructor(honeypotServer) {
    this.#honeypotServer = honeypotServer;
  }

  /**
   * @param {HoneypotServer} honeypotServer
   * @return {ApiServer}
   */
  static create(honeypotServer) {
    const that = new this(honeypotServer);

    const apiServer = http.createServer((req, res) => {
      debugLog("Request: %o %o", req.method, req.url);

      if (req.method === "GET") {
        if (req.url === "/") {
          res.writeHead(200, { "Content-Type": "text/plain" });
          res.end("TXT");
          return;
        }

        // Kamal healthcheck route
        if (req.url === "/up") {
          res.writeHead(200, { "Content-Type": "text/plain" });
          res.end("OK");
          return;
        }
      }

      res.writeHead(404, { "Content-Type": "text/plain" });
      res.end("Not Found");
    });

    that.#server = apiServer;
    return that;
  }

  /**
   * @param {number} [port]
   * @return {ApiServer}
   */
  listen(port, host) {
    port ??= this.#honeypotServer.config.internalApiPort;
    host ??= this.#honeypotServer.config.host;
    this.#server.listen(port, host, () => {
      debugLog(`listening on port ${host}:${port}`);
    });
    return this;
  }

  /**
   * Stop the server if it's running.
   * @return {ApiServer}
   */
  close() {
    try {
      this.#server.close();
    } catch (err) {
      debugLog(`close failed ${err.message}`);
    }
    return this;
  }
}

/**
 * @param {HoneypotServer} honeypot
 * @return {ApiServer}
 */
export const createApiServer = (honeypot) => {
  return ApiServer.create(honeypot);
};
