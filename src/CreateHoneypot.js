import { AbstractHoneypotIntegration } from "./Integrations/AbstractHoneypotIntegration.js";
import { IPList } from "./IPList.js";
import { createApiServer } from "./ApiServer.js";
import { mergeConfigs } from "./utils/config-utils.js";
import debug from "debug";
const debugLog = debug("HoneypotServer");

const DEFAULT_BAN_DURATION_MS = 60 * 60 * 24 * 1000;
const DEFAULT_API_SERVER_PORT = 3477;
const TICK_MS = 1000;
const DEFAULT_API_SERVER_HOST = "0.0.0.0";

export class HoneypotServer {
  /**
   * @type {AbstractHoneypotIntegration[]}
   */
  #integrations = [];

  #attacker;

  /**
   * @type {HoneypotServerConfig}
   */
  #config = {
    port: DEFAULT_API_SERVER_PORT,
    host: DEFAULT_API_SERVER_HOST,
    banDurationMs: DEFAULT_BAN_DURATION_MS,
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
   * @return {IPList}
   */
  get attacker() {
    return (this.#attacker ??= this.#config.attacker ?? new IPList());
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

    setInterval(() => {
      const now = this.attacker.getCurrentTimestamp();
      const keys = this.attacker.ipV4;
      for (const key of keys) {
        const timestamp = this.attacker.getIpV4Timestamp(key);
        if (timestamp !== true && timestamp <= now) {
          debugLog("remove attacker ipV4 entry <%s>", key);
          this.attacker.del(key);
        }
      }

      for (const key of this.attacker.ipV6) {
        const timestamp = this.attacker.getIpV6Timestamp(key);
        if (timestamp !== true && timestamp <= now) {
          debugLog("remove attacker ipV6 entry <%s>", key);
          this.attacker.del(key);
        }
      }
    }, TICK_MS);

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
