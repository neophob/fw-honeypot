import http from "http";
import debug from "debug";
const debugLog = debug("DumpAnalyzer");

export class DumpAnalyzer {
  constructor({
    host = "localhost",
    port = 11434,
    model = "llama3:latest",
    onError = console.error,
    onData = console.info,
  } = {}) {
    this.host = host;
    this.port = port;
    this.model = model;
    this.queue = [];
    this.isProcessing = false;
    this.onError = onError;
    this.onData = onData;
  }

  // Fire-and-forget facade accepting a Tracker instance
  analyseDump(tracker) {
    debugLog(`analyseDump called for ${tracker.ip} ${tracker.serviceName}`);
    if (!tracker || typeof tracker.getTextSummary !== "function") {
      this.onError(
        new Error(
          "analyseDump expects a Tracker instance with getTextSummary()",
        ),
      );
      return;
    }

    const asciiDump = tracker.getTextSummary();
    const metadata = {
      sourceIP: tracker.ip,
      service: tracker.serviceName,
      dumpSize: tracker.getRawDataSize(),
    };

    const task = { asciiDump, metadata };
    this.queue.push(task);
    this.processQueue();
  }

  async processQueue() {
    debugLog(`processQueue: Queue length: ${this.queue.length}`);
    if (this.isProcessing || this.queue.length === 0) return;

    this.isProcessing = true;
    const { asciiDump, metadata } = this.queue.shift();

    try {
      const result = await this.callOllama(asciiDump, metadata);
      this.onData({ asciiDump, metadata, result });
    } catch (err) {
      this.onError(err);
    } finally {
      this.isProcessing = false;
      this.processQueue();
    }
  }

  callOllama(asciiDump, metadata) {
    return new Promise((resolve) => {
      const postData = JSON.stringify({
        model: this.model,
        prompt: this.buildPrompt(asciiDump, metadata),
        stream: false,
      });

      const options = {
        hostname: this.host,
        port: this.port,
        path: "/api/generate",
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(postData),
        },
      };

      const req = http.request(options, (res) => {
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => {
          try {
            debugLog(`Ollama response data: ${data}`);
            const json = JSON.parse(data);

            // If the response contains an error key, treat it as an error
            if (json.error) {
              this.onError(new Error(`Ollama API error: ${json.error}`));
              return resolve(null);
            }

            let parsedResponse = null;
            try {
              parsedResponse = JSON.parse(json.response);
            } catch (innerErr) {
              this.onError(
                new Error("Failed to parse json.response: " + innerErr.message),
              );
            }

            resolve(parsedResponse);
          } catch (err) {
            this.onError(
              new Error("Failed to parse Ollama response: " + err.message),
            );
            resolve(null);
          }
        });
      });

      req.on("error", (err) => {
        this.onError(err);
        resolve(null);
      });

      req.write(postData);
      req.end();
    });
  }

  buildPrompt(asciiDump, metadata) {
    const { sourceIP, service, dumpSize } = metadata;
    return `You are a concise network-forensics analyst. Analyze the following ASCII network traffic dump and produce exactly one or two sentences describing the activity. Include all nerdy technical details: IP addresses, ports, hostnames, shares, protocol/service (${service}), and any other relevant network or OS metadata. Include metadata: source IP (${sourceIP}), service (${service}), dump size (${dumpSize} bytes). Skip null bytes, non-printable characters, and newlines. Output only a strict JSON object with exactly two keys: "analyse" (the 1–2 sentence description) and "threadlevel" (green|yellow|red). Do NOT add any text outside of the JSON object, no headers, no markdown, no explanations.

ASCII_STRINGS:
${asciiDump}`;
  }
}
