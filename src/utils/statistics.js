import debug from "debug";
const debugLog = debug("stats");

class Statistics {
  constructor(options) {
    this.cache = new Map();
    this.nrErrorsToTrack = options?.errorEntriesToTrack ?? 16;
    this.lasterrors = {};
    this.errorSlot = 0;
    this.timeMeasurements = new Map();
    this.maxTimeMeasurements = 32;
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

  addTimeMeasurement(key, value) {
    let measurements = this.timeMeasurements.get(key);
    if (!measurements) {
      measurements = [];
    }
    if (measurements.length >= this.maxTimeMeasurements) {
      measurements.shift();
    }
    measurements.push(value);
    this.timeMeasurements.set(key, measurements);
  }

  calculateAverageTime(key) {
    const measurements = this.timeMeasurements.get(key);
    if (!measurements || measurements.length === 0) {
      return 0;
    }
    const total = measurements.reduce((sum, value) => sum + value, 0);
    return Number(total / measurements.length).toFixed();
  }

  getStatistic() {
    const result = {};
    const allKeys = [...this.cache.keys()];
    allKeys.sort().forEach((key) => {
      result[key] = this.cache.get(key);
    });
    for (const [key] of this.timeMeasurements) {
      result[`${key}_AVG_DURATION_MS`] = this.calculateAverageTime(key);
    }
    const sortedKeys = Object.keys(result).sort();
    const sortedResult = {};
    for (const key of sortedKeys) {
      sortedResult[key] = result[key];
    }
    return sortedResult;
  }

  getLastErrors() {
    return this.lasterrors;
  }

  addErrorMessage(msg) {
    debugLog("error added %s", msg);
    this.lasterrors[this.errorSlot] = msg;
    this.errorSlot = (this.errorSlot + 1) % this.nrErrorsToTrack;
  }

  clearStatistics() {
    this.cache.clear();
    this.lasterrors = {};
    this.timeMeasurements.clear();
  }
}

export const stats = new Statistics();
