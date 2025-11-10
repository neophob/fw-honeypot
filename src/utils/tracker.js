import fs from "fs";
import path from "path";
import debug from "debug";
const debugLog = debug("Tracker");

const INACTIVITY_MS = 120_000; // 120 seconds
const LOG_FILE = path.join(process.env.LOG_DEST || "./", "dump.log");

debugLog(`Dump file: ${LOG_FILE}`);

// Map key: `${ip}|${serviceName}` -> { tracker, timeout }
const dataStore = new Map();

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
      debugLog(`FLUSHIT ${entry.tracker.ip} ${entry.tracker.serviceName}`);
      fs.appendFileSync(
        LOG_FILE,
        entry.tracker.getTextSummary() + "\n\n",
        "utf8",
      );
      //TODO process it
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

  //TODO limit rawData size
  getTextSummary() {
    const str = extractStringsFromHex(this.rawData.join(""));
    return `>#### IP: ${this.ip}, service: ${this.serviceName}, time: ${new Date()}\n${this.rawData.join(" ")}\n${str}`;
  }
}

function extractStringsFromHex(hex) {
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
