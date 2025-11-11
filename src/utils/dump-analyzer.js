import http from "http";
import debug from "debug";
import { stats } from "./statistics.js";

const debugLog = debug("DumpAnalyzer");

export class DumpAnalyzer {
  constructor({
    host = process.env.HOST_OLLAMA ?? "my-honeypot-ollama",
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
    debugLog(`called for ${tracker.ip} ${tracker.serviceName}`);
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
      cutoff: tracker.isCutOff(),
      country: tracker.country,
    };

    const task = { asciiDump, metadata };
    this.queue.push(task);
    stats.setValue("LLM_QUERY_SIZE", this.queue.length);
    this.processQueue();
  }

  async processQueue() {
    if (this.isProcessing || this.queue.length === 0) {
      return;
    }

    this.isProcessing = true;
    const { asciiDump, metadata } = this.queue.shift();

    try {
      stats.increaseCounter("LLM_QUERY_STARTED");
      stats.setValue("LLM_QUERY_SIZE", this.queue.length);
      const llmResult = await this.callOllama(asciiDump, metadata);
      this.onData({ asciiDump, metadata, llmResult });
      stats.increaseCounter("LLM_QUERY_PROCESSED");
    } catch (err) {
      stats.increaseCounter("LLM_QUERY_ERROR");
      this.onError(err);
    } finally {
      this.isProcessing = false;
      this.processQueue();
    }
  }

  test() {
    return this.callOllama(null, null, "say hi");
  }

  failsaveJsonParse(data) {
    try {
      return JSON.parse(data);
    } catch (error) {
      stats.increaseCounter("LLM_INVALID_JSON_DETECTED");
    }

    // Escape lone backslashes (Windows paths etc.)
    const jsonStr = jsonStr.replace(/\\(?!["\\/bfnrtu])/g, "\\\\");
    return JSON5.parse(jsonStr);
  }

  callOllama(asciiDump, metadata, prompt = null) {
    const shouldParseAnswer = prompt === null;
    return new Promise((resolve) => {
      const postData = JSON.stringify({
        model: this.model,
        prompt: prompt ?? this.buildPrompt(asciiDump, metadata),
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
            const json = JSON.parse(data);

            if (json.total_duration) {
              const queryDurationMs = json.total_duration / 1000000;
              stats.addTimeMeasurement("LLM_QUERY", queryDurationMs);
            }

            // If the response contains an error key, treat it as an error
            if (json.error) {
              this.onError(new Error(`Ollama API error: ${json.error}`));
              return resolve(null);
            }

            let parsedResponse = null;
            try {
              parsedResponse = shouldParseAnswer
                ? this.failsaveJsonParse(json.response)
                : json.response;
            } catch (innerErr) {
              debugLog("INVALID_JSON: %s", json.response);
              this.onError(
                new Error("Failed to parse json.response: " + innerErr.message),
              );
            }
            debugLog("Resolve response");
            resolve(parsedResponse);
          } catch (err) {
            debugLog(`Ollama ERROR data: ${data}`);
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
