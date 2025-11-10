import runServer from "./src/server.js";
import { fileURLToPath } from "url";
import { resolve as pathResolve, dirname, resolve } from "path";
import { readConfig } from "./src/Config.js";
import { stats } from "./src/utils/statistics.js";
import debug from "debug";
const debugLog = debug("Root");

// If this module is executed directly (node server.js), start the server.
const entryPath = fileURLToPath(import.meta.url);

process.on("uncaughtException", (err) => {
  debugLog(`Unhandled Exception: ${err}`);
  let firstStackLine = "";
  if (err && err.stack) {
    const lines = err.stack.split("\n");
    if (lines.length > 1) {
      firstStackLine = lines[1].trim(); // usually "at functionName (file:line:col)"
    }
  }
  stats.addErrorMessage(
    `ROOT-EXCEPTION#${err.message}${firstStackLine ? " | " + firstStackLine : ""}`,
  );
});

process.on("unhandledRejection", (reason, promise) => {
  debugLog(`Unhandled Rejection: ${reason}: ${promise}`);
  stats.addErrorMessage(`ROOT-REJECTION#${reason}: ${promise}`);
  process.exit(1);
});

if (
  process.argv[1] &&
  pathResolve(process.argv[1]) === pathResolve(entryPath)
) {
  try {
    const base = resolve(dirname(fileURLToPath(import.meta.url)), ".");
    const config = readConfig(resolve(base, ".env.json"));
    await runServer({ config });
    stats.setValue("START", new Date().toLocaleString());
  } catch (err) {
    debugLog(`Fatal error during startup: ${err.message}`);
    process.exit(1);
  }
}

export default runServer;
