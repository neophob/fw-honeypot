const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;

export class RateLimiter {
  constructor({
    maxConnectionsPerHour = 32,
    windowMs = HOUR,
    blockDurationMs = DAY
  } = {}) {

    this.maxConnectionsPerHour = maxConnectionsPerHour;
    this.windowMs = windowMs;
    this.blockDurationMs = blockDurationMs;

    this.connectionTracker = new Map(); // { ip: { count, firstSeen } }
    this.blocklist = new Map();         // { ip: expiryTimestamp }
  }

  // --- PRIVATE METHODS -------------------------------------------------

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
    if (!expiry) return false;

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

  #block(ip) {
    this.blocklist.set(ip, Date.now() + this.blockDurationMs);
  }

  // --- PUBLIC METHOD ---------------------------------------------------

  checkIfBlocked(ip) {
    this.#cleanup();

    if (this.#isCurrentlyBlocked(ip)) return true;

    const count = this.#incrementConnectionCount(ip);

    if (count > this.maxConnectionsPerHour) {
      this.#block(ip);
      return true;
    }

    return false;
  }
}
