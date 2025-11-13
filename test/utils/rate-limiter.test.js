import test from "node:test";
import assert from "node:assert/strict";
import { RateLimiter } from "../../src/utils/rate-limiter.js";

// Helpers
const hour = 60 * 60 * 1000;
const day = 24 * hour;

test("RateLimiter: allows first connections", () => {
  const limiter = new RateLimiter({
    maxConnectionsPerHour: 3,
    windowMs: hour,
    blockDurationMs: day,
  });

  const ip = "1.2.3.4";

  assert.equal(limiter.checkIfBlocked(ip), false);
  assert.equal(limiter.checkIfBlocked(ip), false);
  assert.equal(limiter.checkIfBlocked(ip), false);
});

test("RateLimiter: blocks when max connections exceeded", () => {
  const limiter = new RateLimiter({
    maxConnectionsPerHour: 3,
    windowMs: hour,
    blockDurationMs: day,
  });

  const ip = "5.6.7.8";

  limiter.checkIfBlocked(ip);
  limiter.checkIfBlocked(ip);
  limiter.checkIfBlocked(ip);

  // 4th connection → should block
  assert.equal(limiter.checkIfBlocked(ip), true);

  // Remains blocked
  assert.equal(limiter.checkIfBlocked(ip), true);
});

test("RateLimiter: unblocks after block duration expires", () => {
  const limiter = new RateLimiter({
    maxConnectionsPerHour: 3,
    windowMs: hour,
    blockDurationMs: day,
  });

  const ip = "9.9.9.9";

  // Trigger block
  limiter.checkIfBlocked(ip);
  limiter.checkIfBlocked(ip);
  limiter.checkIfBlocked(ip);
  assert.equal(limiter.checkIfBlocked(ip), true);

  // Simulate time passing
  const now = Date.now;
  Date.now = () => now() + day + 10; // after block expiry

  // Should be allowed again
  assert.equal(limiter.checkIfBlocked(ip), false);

  // Restore Date.now
  Date.now = now;
});

test("RateLimiter: window resets after 1 hour", () => {
  const limiter = new RateLimiter({
    maxConnectionsPerHour: 3,
    windowMs: hour,
    blockDurationMs: day,
  });

  const ip = "2.2.2.2";

  limiter.checkIfBlocked(ip);
  limiter.checkIfBlocked(ip);
  limiter.checkIfBlocked(ip);

  // Move time forward passed window
  const now = Date.now;
  Date.now = () => now() + hour + 5;

  // Should be allowed again
  assert.equal(limiter.checkIfBlocked(ip), false);

  Date.now = now;
});

test("RateLimiter: cleanup removes expired window & block entries", () => {
  const limiter = new RateLimiter({
    maxConnectionsPerHour: 3,
    windowMs: hour,
    blockDurationMs: day,
  });

  const ip = "3.3.3.3";

  // Hit block threshold
  limiter.checkIfBlocked(ip);
  limiter.checkIfBlocked(ip);
  limiter.checkIfBlocked(ip);
  assert.equal(limiter.checkIfBlocked(ip), true);

  // Move time forward past both window + block expiry
  const now = Date.now;
  Date.now = () => now() + day + hour + 5;

  // Should act as fresh again
  assert.equal(limiter.checkIfBlocked(ip), false);

  Date.now = now;
});
