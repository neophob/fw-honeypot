import runServer from "./src/server.js";
import { fileURLToPath } from "url";
import { resolve as pathResolve, dirname, resolve } from "path";
import { readConfig } from "./src/Config.js";
import { IPList } from "./src/IPList.js";
import { stats } from "./src/utils/statistics.js";
import debug from "debug";
const debugLog = debug("Root");

// If this module is executed directly (node server.js), start the server.
const entryPath = fileURLToPath(import.meta.url);

if (
  process.argv[1] &&
  pathResolve(process.argv[1]) === pathResolve(entryPath)
) {
  try {
    const base = resolve(dirname(fileURLToPath(import.meta.url)), ".");
    const config = readConfig(resolve(base, ".env.json"));
    const attackerList = IPList.loadFromFile(resolve(base, "attacker.json"));
    await runServer({ config, attackerList });

    setInterval(
      () => {
        const statistics = stats.getStatistic();
        const errors = stats.getLastErrors();

        if (Object.keys(statistics).length || Object.keys(errors).length) {
          debugLog("Statistics:", statistics);
          if (Object.keys(errors).length) debugLog("Errors:", errors);
        }
      },
      5 * 60 * 1000,
    );
  } catch (err) {
    console.error(err);
    process.exit(1);
  }
}

export default runServer;
