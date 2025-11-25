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

    stats.increaseCounter("CONNECT_FROM_COUNTRY_" + tracker.country);

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
      debugLog.increaseCounter("LLM_INVALID_RAW_JSON_DETECTED");
    }

    try {
      // Extract substring between first { and last }
      const start = data.indexOf("{");
      const end = data.lastIndexOf("}");
      if (start === -1 || end === -1) {
        stats.increaseCounter("LLM_RESULT_INVALID_JSON");
        return { llmResult: data };
      }
      let jsonStr = data.slice(start, end + 1);
      const fixedJson = JSON.parse(jsonStr);
      return fixedJson;
    } catch (err) {
      stats.addErrorMessage(err.message);
      stats.increaseCounter("LLM_RESULT_PARSE_ERROR");
      return { llmResult: data };
    }
  }

  callOllama(asciiDump, metadata, prompt = null) {
    const shouldParseAnswer = prompt === null;
    return new Promise((resolve) => {
      const postData = JSON.stringify({
        model: this.model,
        prompt: prompt ?? this.buildPrompt(asciiDump, metadata),
        stream: false,
        response_format: "json",
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
    return `
You are a concise, high‑signal network‑forensics analyst specializing in protocol inspection, intrusion‑detection patterns, and MITRE ATT&CK mapping. Your job is to extract forensic meaning from noisy ASCII network‑traffic dumps and describe only what is directly supported by the evidence. You do not speculate beyond observable data.

Analyze the ASCII network‑traffic dump below and produce **exactly one single-line JSON object** with these keys:
- "analyse": 1–2 sentences describing the activity, including all possible technical details supported by the evidence (IP addresses, ports, hostnames, shares, protocol/service (${service}), and any other relevant metadata).
- "threadlevel": one of "green", "yellow", or "red"
- "mitre_phase": the most applicable MITRE ATT&CK phase (e.g., Reconnaissance, Resource Development, Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, Impact)

**Metadata available to you:**
- source IP: ${sourceIP}
- service: ${service}
- dump size: ${dumpSize} bytes

**STRICT RULES:**
- Output **ONLY** a single valid JSON object, no explanations, no commentary, no markdown, no prefixes, nothing before or after.
- JSON must strictly comply with **RFC 8259** (double‑quoted strings, valid escaping, no trailing commas, no comments).
- Remove null bytes, non‑printable characters, and newlines from consideration.
- Only describe what is *literally* visible in the ASCII dump or in the metadata above.
- Do **NOT** invent protocols, commands, hostnames, usernames, or actions that do not explicitly appear.
- If evidence is missing or ambiguous, state "unknown" or leave that detail out, but still produce valid JSON.
- Before producing the JSON, verify that every claim in "analyse" is directly supported by the ASCII strings or given metadata.

**Example (format only; do not copy content):**
{"analyse":"ASCII dump contains string 'abc123' with no clear protocol.","threadlevel":"green","mitre_phase":"Reconnaissance"}

ASCII_STRINGS:
${asciiDump}
`;
  }
}
