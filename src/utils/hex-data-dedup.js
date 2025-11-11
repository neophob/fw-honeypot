import debug from "debug";
const debugLog = debug("HexDeDup");

export class HexDataDeduplicator {
  constructor(
    bufferSize = 100,
    similarityThreshold = 0.8,
    maxDataSize = 3 * 1024,
  ) {
    this.bufferSize = bufferSize;
    this.similarityThreshold = similarityThreshold;
    this.maxDataSize = maxDataSize; // max raw data size in bytes
    this.buffer = new Array(bufferSize);
    this.index = 0;
    debugLog(
      `initialized with bufferSize=${bufferSize}, similarityThreshold=${similarityThreshold}`,
    );
  }

  // Public method
  isUniqueData(hex, optionalDebugDetails = "") {
    const newBytes = this.#hexToBytes(hex);

    for (const oldHex of this.buffer) {
      if (!oldHex) continue;
      const oldBytes = this.#hexToBytes(oldHex);
      const similarity = this.#arraySimilarity(newBytes, oldBytes);
      if (similarity >= this.similarityThreshold) {
        debugLog(
          `Data too similar (similarity=${similarity.toFixed(2)}) to existing entry ${optionalDebugDetails}.`,
        );
        return false;
      }
    }

    // unique enough → add to buffer
    debugLog("Data is unique!");
    this.buffer[this.index] = hex;
    this.index = (this.index + 1) % this.bufferSize;
    return true;
  }

  // --- private helpers ---
  #hexToBytes(hexStr) {
    const bytes = [];
    for (let i = 0; i < hexStr.length; i += 2) {
      bytes.push(parseInt(hexStr.slice(i, i + 2), 16));
    }
    return bytes;
  }

  #arraySimilarity(arr1, arr2) {
    const len = Math.min(arr1.length, arr2.length);
    let diff = Math.abs(arr1.length - arr2.length);
    for (let i = 0; i < len; i++) {
      if (arr1[i] !== arr2[i]) diff++;
    }
    return 1 - diff / Math.max(arr1.length, arr2.length);
  }
}
