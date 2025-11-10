import test from "node:test";
import assert from "node:assert/strict";
import { HexDataDeduplicator } from "../../src/utils/hex-data-dedup.js";

test("isUniqueData returns true for first hex array", () => {
  const deduplicator = new HexDataDeduplicator(3, 0.8);
  const hex = "ff00a1";
  const result = deduplicator.isUniqueData(hex);
  assert.equal(result, true);
});

test("isUniqueData returns false for identical hex array", () => {
  const deduplicator = new HexDataDeduplicator(3, 0.9);
  const hex = "ff00a1";
  deduplicator.isUniqueData(hex);
  const result = deduplicator.isUniqueData(hex);
  assert.equal(result, false);
});

test("isUniqueData returns true for slightly different hex array", () => {
  const deduplicator = new HexDataDeduplicator(3, 0.9);
  const hex1 = "ff00a1";
  const hex2 = "ff00a2"; // slight difference
  deduplicator.isUniqueData(hex1);
  const result = deduplicator.isUniqueData(hex2);
  assert.equal(result, true);
});

test("circular buffer overwrites oldest entry", () => {
  const deduplicator = new HexDataDeduplicator(2, 0.5);
  deduplicator.isUniqueData("a1");
  deduplicator.isUniqueData("b2");
  deduplicator.isUniqueData("c3"); // should overwrite "a1"

  const buffer = deduplicator.buffer;
  assert.deepEqual(buffer, ["c3", "b2"]); // circular overwrite
});

test("isUniqueData works for arrays of different lengths", () => {
  const deduplicator = new HexDataDeduplicator(3, 0.8);
  const hex1 = "ff00a1";
  const hex2 = "ff00a1ff"; // longer array
  deduplicator.isUniqueData(hex1);
  const result = deduplicator.isUniqueData(hex2);
  assert.equal(result, true); // considered different enough
});

test("multiple hex arrays processed correctly", () => {
  const deduplicator = new HexDataDeduplicator(3, 0.8);
  const data = ["aa", "bb", "cc", "aa", "dd"];
  const results = data.map((h) => deduplicator.isUniqueData(h));
  assert.deepEqual(results, [true, true, true, false, true]);
});
