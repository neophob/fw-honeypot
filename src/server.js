import { createHoneypot as _createHoneypot } from "./CreateHoneypot.js";
import { HoneypotSshServerIntegration } from "./Integrations/HoneypotSshServerIntegration.js";
import { HoneypotSmtpServerIntegration } from "./Integrations/HoneypotSmtpServerIntegration.js";
import { HoneypotTelnetServerIntegration } from "./Integrations/HoneypotTelnetServerIntegration.js";
import { HoneypotMySQLServerIntegration } from "./Integrations/HoneypotMySQLServerIntegration.js";
import { HoneypotSMBServerIntegration } from "./Integrations/HoneypotSMBServerIntegration.js";
import { HoneypotRdpServerIntegration } from "./Integrations/HoneypotRdpServerIntegration.js";

/**
 * Start the honeypot server. Accepts optional dependency overrides to make testing safe.
 * @param {object} deps
 */
export async function runServer(deps = {}) {
  const createHoneypot = deps.createHoneypot ?? _createHoneypot;
  const config = deps.config;
  const integrationMap = deps.integrationMap ?? {
    HoneypotSshServerIntegration,
    HoneypotSmtpServerIntegration,
    HoneypotTelnetServerIntegration,
    HoneypotMySQLServerIntegration,
    HoneypotSMBServerIntegration,
    HoneypotRdpServerIntegration,
  };

  if (!config) throw new Error("Config must be provided to runServer");
  config.honeypot = config.honeypot ?? {};

  const integrations = (config.integrations || []).map((integration) => {
    if (typeof integration === "string") {
      integration = { name: integration };
    }
    const Cls = integrationMap[integration.name];
    return new Cls(integration.config);
  });

  await createHoneypot(integrations, config.honeypot).run();
}

export default runServer;
