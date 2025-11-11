import test from "node:test";
import assert from "node:assert/strict";
import { stats } from "../../src/utils/statistics.js";

test("Statistics: sets and retrieves values correctly", () => {
  stats.clearStatistics();
  stats.setValue("users", 5);
  assert.deepEqual(stats.getStatistic(), { users: 5 });
});

test("Statistics: increases counters correctly", () => {
  stats.clearStatistics();
  stats.increaseCounter("hits");
  stats.increaseCounter("hits", 2);
  assert.deepEqual(stats.getStatistic(), { hits: 3 });
});

test("Statistics: tracks last errors correctly", () => {
  stats.clearStatistics();
  stats.addErrorMessage("Error A");
  stats.addErrorMessage("Error B");
  const errors = stats.getLastErrors();
  assert.ok(Object.values(errors).includes("Error A"));
  assert.ok(Object.values(errors).includes("Error B"));
});

test("Statistics: clears statistics properly", () => {
  stats.setValue("foo", 1);
  stats.addErrorMessage("oops");
  stats.clearStatistics();
  assert.deepEqual(stats.getStatistic(), {});
  assert.deepEqual(stats.getLastErrors(), {});
});

test("Statistics: time measurements", () => {
  stats.clearStatistics();
  stats.addTimeMeasurement("query1", 100);
  stats.addTimeMeasurement("query1", 200);
  stats.addTimeMeasurement("query1", 300);
  assert.equal(stats.calculateAverageTime("query1"), '200');
});

test("Statistics: summary", () => {
  stats.clearStatistics();
  stats.setValue("requests", 42);
  stats.addTimeMeasurement("requests", 120);
  stats.addTimeMeasurement("requests", 240);
  assert.deepEqual(stats.getStatistic(), {
    requests: 42,
    requests_AVG_DURATION_MS: '180',
  });
});

test("Statistics: supports custom errorEntriesToTrack", () => {
  stats.clearStatistics();
  for (let i = 0; i < 20; i++) {
    stats.addErrorMessage(`Error ${i}`);
  }
  assert.equal(Object.keys(stats.getLastErrors()).length, 16);
});
