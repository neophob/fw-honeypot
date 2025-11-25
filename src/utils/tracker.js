import fs from "fs";
import path from "path";
import debug from "debug";
import geoip from "geoip-country";
import { stats } from "./statistics.js";
import { HexDataDeduplicator } from "./hex-data-dedup.js";
import { DumpAnalyzer } from "./dump-analyzer.js";
import {
  sendTelegramMessage,
  formatLlmDataForTelegram,
} from "./telegram-bot.js";

const debugLog = debug("Tracker");
const INACTIVITY_MS = process.env.INACTIVITY_MS
  ? parseInt(process.env.INACTIVITY_MS, 10)
  : 120_000;
//TODO fix naming
const LOG_FILE = path.join(process.env.LOG_DEST || "./", "dump-raw.log");
const LLM_LOG_FILE = path.join(process.env.LLM_DEST || "./", "dump-llm.log");
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID;

debugLog(
  `Dump file: "${LOG_FILE}", LLM file: "${LLM_LOG_FILE}", inactivity timeout: ${INACTIVITY_MS}ms, Telegram chat ID: <${TELEGRAM_CHAT_ID}>`,
);
const deduplicator = new HexDataDeduplicator(100, 0.8);
const dataStore = new Map();
const analyzer = new DumpAnalyzer({
  onError: (err) => {
    stats.increaseCounter("LLM_ANALYZED_FAILED");
    stats.addErrorMessage(`LLM-ERROR#${err.message}`);
    debugLog(`LLM error: %O`, err);
  },
  onData: ({ asciiDump, metadata, llmResult, printableString }) => {
    stats.increaseCounter("LLM_ANALYZED_DATA");
    debugLog("ANALYZED_LLM_DUMPS: %o, %o, %o", asciiDump, metadata, llmResult);
    fs.appendFileSync(
      LLM_LOG_FILE,
      JSON.stringify({ asciiDump, metadata, llmResult }, null, 2) + "\n\n",
      "utf8",
    );
    if (llmResult?.threadlevel) {
      stats.increaseCounter(
        `LLM_THREADLEVEL_${llmResult.threadlevel.toString().toUpperCase()}`,
      );
    }

    // Send to Telegram bot
    if (TELEGRAM_BOT_TOKEN && TELEGRAM_CHAT_ID) {
      const telegramMessage = formatLlmDataForTelegram(
        printableString,
        metadata,
        llmResult,
      );
      sendTelegramMessage(TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, telegramMessage)
        .then(() => {
          stats.increaseCounter("TELEGRAM_MESSAGE_SENT");
          debugLog("Successfully sent message to Telegram");
        })
        .catch((err) => {
          stats.increaseCounter("TELEGRAM_MESSAGE_FAILED");
          stats.addErrorMessage(`TELEGRAM-ERROR#${err.message}`);
          debugLog("Failed to send message to Telegram: %O", err);
        });
    } else {
      debugLog(
        "Telegram bot not configured (missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID)",
      );
    }
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
    stats.increaseCounter("TRACKER_TIMEOUT_REACHED");
    try {
      const dataIsUnique = deduplicator.isUniqueData(
        entry.tracker.getHexString(),
        entry.tracker.serviceName,
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
    this.ip = ip.toString();
    this.serviceName = serviceName;
    this.rawData = [];
    this.maxDataSize = maxDataSize;
    this.country = "Unknown";
    const geo = geoip.lookup(this.ip);
    if (geo?.country) {
      this.country = geo.country;
    }
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

  getTextSummary() {
    const time = new Date().toLocaleString();
    const cutoff = this.isCutOff();
    const hexStr = this.getHexString();
    const printableStr = this.getPrintableString();
    return `## IP: ${this.ip}, country: ${this.country}, service: ${this.serviceName}, size: ${this.getRawDataSize()}, time: ${time}, cutoff: ${cutoff}\n${hexStr}\n${printableStr}`;
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
