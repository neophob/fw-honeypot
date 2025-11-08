export type HoneypotServerConfig = {
  port?: number;
  host?: string;
  ipV4?: boolean;
  ipV6?: boolean;
};

type HoneypotIntegrationConfig = {
  name: string;
  config: HoneypotServerConfig;
};

export type HoneypotEnvironmentConfig = {
  integrations: (HoneypotIntegrationConfig | string)[];
  honeypot: HoneypotServerConfig;
};
