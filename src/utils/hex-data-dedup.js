import debug from "debug";
const debugLog = debug("HexDeDup");
/*
    this.ip = ip;
    this.serviceName = serviceName;
    this.rawData = [];

    Analyse step by step
    - base64 encode the raw data's
    - for each rawData: send to LLM for analysis: Analyze this base64 encoded ${serviceName} network traffic. RETURN ONLY ONE or TWO SENTENCES describing the activity including all the technical details (target ips, names, ports, network details - just the nerdy stuff but make sure to skip newline characters, null bytes or non printable characters). DO NOT EXPLAIN STEPS OR ADD EXTRA TEXT. OUTPUT SHOULD START WITH: \"RESULT: \" Followed by the sentence.\n\nBase64: ${data}
    - collect all the results, generate the master query

Analyze the traffic my honeypot received. Identify the intent of the commands in one concise sentence. Classify the threat level as a color (red/yellow/green) where red is the most malicious. Guess the attacker's origin country if possible, otherwise write N/A.

Return the answer strictly in this format:

Summary: <one-sentence summary of attacker activity>
Color: <red/yellow/green>
Origin (guess): <country or N/A, with optional justification in parentheses>
Do not include raw packet data, hex, or any extra information.

*/

export class HexDataDeduplicator {
  constructor(bufferSize = 100, similarityThreshold = 0.8) {
    this.bufferSize = bufferSize;
    this.similarityThreshold = similarityThreshold;
    this.buffer = new Array(bufferSize);
    this.index = 0;
    debugLog(
      `initialized with bufferSize=${bufferSize}, similarityThreshold=${similarityThreshold}`,
    );
  }

  // Public function: check if new hex is unique enough
  // Returns true if it is, and adds it to the buffer
  isUniqueData(hex) {
    const newBytes = this.#hexToBytes(hex);

    for (const oldHex of this.buffer) {
      if (!oldHex) continue;
      const oldBytes = this.#hexToBytes(oldHex);
      const similarity = this.#arraySimilarity(newBytes, oldBytes);
      if (similarity >= this.similarityThreshold) {
        debugLog(
          `Data too similar (similarity=${similarity.toFixed(2)}) to existing entry, rejecting.`,
        );
        return false; // too similar, not unique
      }
    }

    // unique enough → add to buffer
    debugLog("Data is unique enough, adding to buffer.");
    this.buffer[this.index] = hex;
    this.index = (this.index + 1) % this.bufferSize;
    return true;
  }

  // --- internal helper functions ---

  #hexToBytes(hexStr) {
    const bytes = [];
    for (let i = 0; i < hexStr.length; i += 2) {
      bytes.push(parseInt(hexStr.slice(i, i + 2), 16));
    }
    return bytes;
  }

  #arraySimilarity(arr1, arr2) {
    const len = Math.min(arr1.length, arr2.length);
    let diff = Math.abs(arr1.length - arr2.length); // account for length difference
    for (let i = 0; i < len; i++) {
      if (arr1[i] !== arr2[i]) diff++;
    }
    return 1 - diff / Math.max(arr1.length, arr2.length);
  }
}
