// test.js
import test from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import { track, clean } from "../../src/utils/tracker.js";

// --- Mock fs.appendFileSync ---
const originalAppend = fs.appendFileSync;
let lastWrite = null;
fs.appendFileSync = (filePath, content) => {
  lastWrite = { filePath, content };
};

// --- Helper: fast-forward wait (simulate inactivity) ---
function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// --- Tests ---

test("Tracker: single flush after inactivity", async () => {
  clean();
  lastWrite = null;
  const ip = "127.0.0.1";
  const service = "ssh";
  const data = "login attempt";

  track(ip, service, data, 20);
  await wait(50);

  assert(lastWrite, "Expected flush to happen");
  assert(lastWrite.content.includes(ip), "IP should be in flush");
  assert(lastWrite.content.includes(service), "Service should be in flush");
  assert(lastWrite.content.includes(data), "Data should be in flush");
});

test("Tracker: multiple data entries flushed together", async () => {
  clean();
  lastWrite = null;

  const ip = "10.0.0.5";
  const service = "http";

  track(ip, service, "GET /index.html", 200);
  track(ip, service, "POST /login", 100);

  await wait(400);

  assert(lastWrite.content.includes("GET /index.html"), "First entry missing");
  assert(lastWrite.content.includes("POST /login"), "Second entry missing");
});

test("Tracker: clean cancels timers", async () => {
  lastWrite = null;

  track("1.1.1.1", "ssh", "test", 20);
  clean();

  assert(lastWrite === null, "Flush should not happen after clean");
});

// --- Cleanup ---
test("Tracker: cleanup mock", () => {
  clean();
  fs.appendFileSync = originalAppend;
});
