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

  track(ip, service, "00000045ff534d4272000000001801c8000000000000000000000000ffff000000000000002200024e54204c4d20302e31320002534d4220322e3030320002534d4220322e3f3f3f00", 200);
  track(ip, service, "5353482d322e302d476f0d0a", 100);

  await wait(400);
  assert(lastWrite.content.includes("45ff534d4272000000001801c80000"), "First entry missing");
  assert(lastWrite.content.includes("5353482d322e302d476f0d0a"), "Second entry missing");
});

test("Tracker: remove duplicates", async () => {
  clean();
  lastWrite = null;

  const ip = "10.0.0.5";
  const service = "http";
  const data = "PAYLOAD";

  track(ip, service, data, 200);
  track(ip, service, data, 200);
  track(ip, service, data, 100);

  await wait(400);
  assert(lastWrite.content.includes("\nPAYLOAD\n\n"));
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
