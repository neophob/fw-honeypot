import fs from "fs";
import path from "path";
import debug from "debug";
const debugLog = debug("Tracker");
import { stats } from "./statistics.js";
import { HexDataDeduplicator } from "./hex-data-dedup.js";
import { DumpAnalyzer } from "./dump-analyzer.js";

const INACTIVITY_MS = process.env.INACTIVITY_MS
  ? parseInt(process.env.INACTIVITY_MS, 10)
  : 120_000;
//TODO fix naming
const LOG_FILE = path.join(process.env.LOG_DEST || "./", "dump-raw.log");
const LLM_LOG_FILE = path.join(process.env.LLM_DEST || "./", "dump-llm.log");

debugLog(
  `Dump file: ${LOG_FILE}, LLM file: ${LLM_LOG_FILE}, inactivity timeout: ${INACTIVITY_MS}ms`,
);
const deduplicator = new HexDataDeduplicator(100, 0.8);
const dataStore = new Map();
const analyzer = new DumpAnalyzer({
  onError: (err) => {
    stats.increaseCounter("FAILED_LLM_ANALYZE");
    debugLog(`LLM error: %O`, err);
  },
  onData: ({ asciiDump, metadata, llmResult }) => {
    stats.increaseCounter("ANALYZED_LLM_DUMPS");
    debugLog("ANALYZED_LLM_DUMPS: %o, %o, %o", asciiDump, metadata, llmResult);
    fs.appendFileSync(
      LLM_LOG_FILE,
      JSON.stringify({ asciiDump, metadata, llmResult }, null, 2) + "\n\n",
      "utf8",
    );
  },
});

setTimeout(async () => {
  debugLog("Test LLM");
  await analyzer.test();
}, 5000);

function makeKey(ip, serviceName) {
  return `${ip}|${serviceName}`;
}

export function track(ip, serviceName, data, timeoutMs = INACTIVITY_MS) {
  const key = makeKey(ip, serviceName);
  let entry = dataStore.get(key);
  if (!entry) {
    debugLog(`create new tracker for ${ip} ${serviceName}`);
    stats.increaseCounter("TRACKER_CREATED");
    const tracker = new Tracker(ip, serviceName);
    entry = {
      tracker,
      timeout: null,
    };
    dataStore.set(key, entry);
  }
  entry.tracker.addData(data);

  if (entry.timeout) {
    stats.increaseCounter("TRACKER_TIMEOUT_CLEARED");
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
  stats.increaseCounter("TRACKER_TIMEOUT_CREATED");
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
  constructor(ip, serviceName, maxDataSize = 3 * 1024) {
    this.ip = ip;
    this.serviceName = serviceName;
    this.rawData = [];
    this.maxDataSize = maxDataSize;
  }

  //TODO rename to addHexStringData
  addData(data) {
    if (data && !this.rawData.includes(data)) {
      this.rawData.push(data);
      stats.increaseCounter("TRACKER_DATA_PUSHED");
    } else {
      stats.increaseCounter("TRACKER_DATA_IGNORED_DUPLICATE");
    }
  }

  getRawDataSize() {
    const hexStr = this.rawData.join("");
    return Math.floor(hexStr.length / 2);
  }

  // return string, respect maxDataSize
  getCutoffString(joinString = "") {
    if (this.getRawDataSize() <= this.maxDataSize) {
      return this.rawData.join(joinString);
    }
    return this.rawData.join(joinString).slice(0, this.maxDataSize * 2);
  }

  getHexString() {
    return this.getCutoffString(" ");
  }

  getPrintableString() {
    return Tracker.#extractStringsFromHex(this.getCutoffString(""));
  }

  isCutOff() {
    return this.getRawDataSize() > this.maxDataSize;
  }

  //TODO limit rawData size
  getTextSummary() {
    const time = new Date().toLocaleString();
    const cutoff = this.isCutOff();
    const hexStr = this.getHexString();
    const printableStr = this.getPrintableString();
    return `## IP: ${this.ip}, service: ${this.serviceName}, size: ${this.getRawDataSize()}, time: ${time}, cutoff: ${cutoff}\n${hexStr}\n${printableStr}`;
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
