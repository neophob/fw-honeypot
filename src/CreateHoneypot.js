import { AbstractHoneypotIntegration } from "./Integrations/AbstractHoneypotIntegration.js";
import { createApiServer } from "./ApiServer.js";
import { mergeConfigs } from "./utils/config-utils.js";
import debug from "debug";
const debugLog = debug("HoneypotServer");

const DEFAULT_INTERNAL_API_PORT = 3477;
const DEFAULT_API_SERVER_HOST = "0.0.0.0";

export class HoneypotServer {
  /**
   * @type {AbstractHoneypotIntegration[]}
   */
  #integrations = [];

  /**
   * @type {HoneypotServerConfig}
   */
  #config = {
    internalApiPort: DEFAULT_INTERNAL_API_PORT,
    host: DEFAULT_API_SERVER_HOST,
  };
  #apiServer;

  /**
   * @param {AbstractHoneypotIntegration[]} abstractHoneypotIntegration
   * @param {HoneypotServerConfig} config
   */
  constructor(abstractHoneypotIntegration, config) {
    config ??= {};
    this.#integrations = abstractHoneypotIntegration;
    this.#config = mergeConfigs(this.#config, config);
    debugLog("Config: <%o>", this.#config);
  }

  /**
   * @return {HoneypotServerConfig}
   */
  get config() {
    return this.#config;
  }

  /**
   * @return {ApiServer}
   */
  get apiServer() {
    return (this.#apiServer ??= createApiServer(this));
  }

  /**
   * @return {Promise<HoneypotServer>}
   */
  async run() {
    for (const integration of this.#integrations) {
      await integration.create(this);
      await integration.listen();
    }

    this.apiServer.listen();
    return this;
  }
}

/**
 * @param {AbstractHoneypotIntegration[]} abstractHoneypotIntegrations
 * @param {HoneypotServerConfig} config
 * @return {HoneypotServer}
 */
export const createHoneypot = (abstractHoneypotIntegrations, config) => {
  return new HoneypotServer(abstractHoneypotIntegrations, config);
};
