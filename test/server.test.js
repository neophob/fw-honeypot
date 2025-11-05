import test from "node:test";
import assert from "node:assert/strict";

import { runServer } from "../src/server.js";

test("GIVEN a minimal config WHEN runServer is called THEN createHoneypot.run is invoked with created integrations and honeypot config", async () => {
  // GIVEN: stub dependencies
  let createHoneypotArgs = null;
  let runCalled = false;

  const DummyIntegration = class {
    constructor(cfg) {
      this.cfg = cfg;
    }
  };

  const readConfig = (path) => {
    return {
      integrations: [{ name: "Dummy" }],
      honeypot: { internalApiPort: 1234 },
    };
  };

  const IPList = {
    loadFromFile: () => ({ prefilled: true }),
  };

  const createHoneypot = (integrations, honeypot) => {
    createHoneypotArgs = { integrations, honeypot };
    return {
      run: async () => {
        runCalled = true;
      },
    };
  };

  const deps = {
    readConfig,
    IPList,
    createHoneypot,
    // make path helpers trivial since our stubs don't use the paths
    fileURLToPath: () => "/",
    dirname: () => "/",
    resolve: (_, p) => p,
    integrationMap: {
      Dummy: DummyIntegration,
    },
    config: readConfig(),
    attackerList: IPList.loadFromFile(),
  };

  // WHEN
  await runServer(deps);

  // THEN
  assert.ok(runCalled, "createHoneypot.run should have been called");
  assert.ok(
    Array.isArray(createHoneypotArgs.integrations),
    "integrations should be an array",
  );
  assert.equal(createHoneypotArgs.integrations.length, 1);
  assert.ok(
    createHoneypotArgs.honeypot.attacker.prefilled,
    "honeypot should have attacker prefilled",
  );
  assert.ok(
    createHoneypotArgs.integrations[0] instanceof DummyIntegration,
    "integration instance should be created from map",
  );
});
