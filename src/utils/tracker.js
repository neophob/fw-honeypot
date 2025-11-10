import fs from "fs";
import path from "path";
import debug from "debug";
const debugLog = debug("Tracker");
import { HexDataDeduplicator } from "./hex-data-dedup.js";
import { DumpAnalyzer } from "./dump-analyzer.js";

const INACTIVITY_MS = process.env.INACTIVITY_MS
  ? parseInt(process.env.INACTIVITY_MS, 10)
  : 120_000;
const LOG_FILE = path.join(process.env.LOG_DEST || "./", "dump.log");
const LLM_LOG_FILE = path.join(process.env.LLM_DEST || "./", "dumpLlm.log");

debugLog(`Dump file: ${LOG_FILE}, LLM file: ${LLM_LOG_FILE}, inactivity timeout: ${INACTIVITY_MS}ms`);
const deduplicator = new HexDataDeduplicator(100, 0.8);
const dataStore = new Map();
const analyzer = new DumpAnalyzer({
  onError: (err) => debugLog(`LLM error: ${err.message}`),
  onData: (asciiDump, metadata, llmAnswer) => {
    debugLog("%o, %o, %o", asciiDump, metadata, llmAnswer);
    fs.appendFileSync(
      LLM_LOG_FILE,
      JSON.stringify({ asciiDump, metadata, llmAnswer }, null, 2) + "\n\n",
      "utf8",
    );
  },
});

function makeKey(ip, serviceName) {
  return `${ip}|${serviceName}`;
}

export function track(ip, serviceName, data, timeoutMs = INACTIVITY_MS) {
  const key = makeKey(ip, serviceName);
  let entry = dataStore.get(key);
  if (!entry) {
    debugLog(`create new tracker for ${ip} ${serviceName}`);
    const tracker = new Tracker(ip, serviceName);
    entry = {
      tracker,
      timeout: null,
    };
    dataStore.set(key, entry);
  }
  entry.tracker.addData(data);

  if (entry.timeout) {
    debugLog(`Clear timeout`);
    clearTimeout(entry.timeout);
  }
  entry.timeout = setTimeout(async () => {
    try {
      const dataIsUnique = deduplicator.isUniqueData(
        entry.tracker.getHexString(),
      );

      if (dataIsUnique) {
        debugLog(`FLUSHIT ${entry.tracker.ip} ${entry.tracker.serviceName}`);
        fs.appendFileSync(
          LOG_FILE,
          entry.tracker.getTextSummary() + "\n\n",
          "utf8",
        );
        analyzer.analyseDump(entry.tracker);
      }
    } catch (err) {
      debugLog(`Error flushing tracker for ${key}: ${err.message}`);
    } finally {
      dataStore.delete(key);
    }
  }, timeoutMs);
}

export function clean() {
  debug("Cleaning up trackers");
  for (const [key, entry] of dataStore) {
    // Cancel the timer if it exists
    if (entry.timeout) {
      clearTimeout(entry.timeout);
      entry.timeout = null;
    }
  }
  dataStore.clear();
}

export class Tracker {
  constructor(ip, serviceName) {
    this.ip = ip;
    this.serviceName = serviceName;
    this.rawData = [];
  }

  addData(data) {
    if (!this.rawData.includes(data)) {
      this.rawData.push(data);
    }
  }

  getHexString() {
    return this.rawData.join(" ");
  }

  getRawDataSize() {
    const hexStr = this.rawData.join("");
    return Math.floor(hexStr.length / 2);
  }

  //TODO limit rawData size
  getTextSummary() {
    const str = Tracker.#extractStringsFromHex(this.rawData.join(""));
    return `## IP: ${this.ip}, service: ${this.serviceName}, size: ${this.getRawDataSize()}, time: ${new Date().toLocaleString()}\n${this.getHexString()}\n${str}`;
  }

  // Private static method
  static #extractStringsFromHex(hex) {
    const buf = Buffer.from(hex.replace(/[^0-9a-fA-F]/g, ""), "hex");

    let result = "";
    for (let i = 0; i < buf.length; i++) {
      const b = buf[i];
      // Check if printable ASCII
      if (b >= 0x20 && b <= 0x7e) {
        result += String.fromCharCode(b);
      } else {
        // Replace non-printable with space
        result += " ";
      }
    }
    // Collapse multiple spaces
    return result.replace(/\s+/g, " ").trim();
  }
}
