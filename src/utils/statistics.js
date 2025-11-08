import debug from "debug";
const debugLog = debug("stats");

class Statistics {
  constructor(options) {
    this.cache = new Map();
    this.nrErrorsToTrack = options?.errorEntriesToTrack ?? 16;
    this.lasterrors = {};
    this.errorSlot = 0;

    setInterval(
      () => {
        const stats = this.getStatistic();
        const errors = this.getLastErrors();

        if (Object.keys(stats).length || Object.keys(errors).length) {
          debug("Statistics:", stats);
          if (Object.keys(errors).length) debug("Errors:", errors);
        }
      },
      5 * 60 * 1000,
    );
  }

  setValue(key, value) {
    this.cache.set(key, value);
  }

  increaseCounter(key, amount) {
    const _amount = amount || 1;
    let value = this.cache.get(key);
    if (!Number.isInteger(value)) {
      value = _amount;
    } else {
      value += _amount;
    }
    this.cache.set(key, value);
  }

  getStatistic() {
    const result = {};
    const allKeys = Array.from(this.cache.keys());
    allKeys.sort().forEach((key) => {
      result[key] = this.cache.get(key);
    });
    return result;
  }

  getLastErrors() {
    return this.lasterrors;
  }

  addErrorMessage(msg) {
    this.lasterrors[this.errorSlot] = msg;
    this.errorSlot = (this.errorSlot + 1) % this.nrErrorsToTrack;
  }

  clearStatistics() {
    this.cache.clear();
    this.lasterrors = {};
  }
}

const statisticsInstance = new Statistics();

// Export both the class and the singleton instance
export { Statistics };
export default statisticsInstance;
