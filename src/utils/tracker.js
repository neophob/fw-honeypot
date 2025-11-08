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
      debugLog(`FLUSHIT ${entry.tracker.getTextSummary()}`);
      fs.appendFileSync(LOG_FILE, entry.tracker.getTextSummary() + "\n", "utf8");
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

class Tracker {
  constructor(ip, serviceName) {
    this.ip = ip;
    this.serviceName = serviceName;
    this.rawData = [];
  }

  addData(data) {
    this.rawData.push(data);
  }

  getTextSummary() {
    return `IP: ${this.ip}, service ${this.serviceName}\n${this.rawData.join(" ")}`;
  }
}
