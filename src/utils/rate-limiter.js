import debug from "debug";

const debugLog = debug("RateLimiter");
const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;

const CONNECTION_PER_HOURS = process.env.CONNECTION_PER_HOURS
  ? parseInt(process.env.CONNECTION_PER_HOURS, 10)
  : 32;

export class RateLimiter {
  constructor({
    maxConnectionsPerHour = CONNECTION_PER_HOURS,
    windowMs = HOUR,
    blockDurationMs = DAY,
  } = {}) {
    this.maxConnectionsPerHour = maxConnectionsPerHour;
    this.windowMs = windowMs;
    this.blockDurationMs = blockDurationMs;

    this.connectionTracker = new Map(); // { ip: { count, firstSeen } }
    this.blocklist = new Map(); // { ip: expiryTimestamp }
    debugLog(`created maxConnectionsPerHour: ${maxConnectionsPerHour}`);
  }

  #cleanup() {
    const now = Date.now();

    for (const [ip, entry] of this.connectionTracker.entries()) {
      if (now - entry.firstSeen > this.windowMs) {
        this.connectionTracker.delete(ip);
      }
    }

    for (const [ip, expiry] of this.blocklist.entries()) {
      if (expiry < now) {
        this.blocklist.delete(ip);
      }
    }
  }

  #isCurrentlyBlocked(ip) {
    const expiry = this.blocklist.get(ip);
    if (!expiry) {
      return false;
    }

    if (expiry < Date.now()) {
      this.blocklist.delete(ip);
      return false;
    }
    return true;
  }

  #incrementConnectionCount(ip) {
    const now = Date.now();
    const entry = this.connectionTracker.get(ip);

    if (!entry || now - entry.firstSeen > this.windowMs) {
      this.connectionTracker.set(ip, { count: 1, firstSeen: now });
      return 1;
    }

    entry.count++;
    return entry.count;
  }

  checkIfBlocked(_ip) {
    const ip = _ip.toString();
    this.#cleanup();

    if (this.#isCurrentlyBlocked(ip)) {
      debugLog(`IP ${ip} is currently blocked`);
      return true;
    }

    const count = this.#incrementConnectionCount(ip);
    if (count > this.maxConnectionsPerHour) {
      this.blocklist.set(ip, Date.now() + this.blockDurationMs);
      debugLog(`IP ${ip} is now blocked`);
      return true;
    }

    debugLog(`IP ${ip} is not blocked, ${count} connections`);
    return false;
  }
}
