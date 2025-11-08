import { AbstractHoneypotIntegration } from "./AbstractHoneypotIntegration.js";
import { HoneypotServer } from "../CreateHoneypot.js";
import { mergeConfigs } from "../utils/config-utils.js";
import { stats } from "../utils/statistics.js";
import debug from "debug";
const debugLog = debug("SMB");
import net from "net";

const SMB_BANNER = Buffer.from([
  0xff,
  0x53,
  0x4d,
  0x42, // "SMB" Header
  0x72, // Command (Negotiate Protocol)
]);

export class HoneypotSMBServerIntegration extends AbstractHoneypotIntegration {
  #server;

  /**
   * @type {HoneypotServerConfig}
   */
  #config = {
    port: 445,
  };

  constructor(config) {
    super();
    this.config = mergeConfigs(this.config, config);
  }

  /**
   * @return {HoneypotServerConfig}
   */
  get config() {
    return this.#config;
  }

  set config(config) {
    this.#config = config;
  }

  /**
   * @param {HoneypotServer} honeypotServer
   */
  create(honeypotServer) {
    const config = mergeConfigs(honeypotServer.config, this.config);
    this.config = config;
    debugLog("Config: <%o>", this.config);

    this.#server = net.createServer((socket) => {
      const ip = socket.remoteAddress;
      debugLog(`New connection from %o`, socket.address());
      stats.increaseCounter("SMB_CONNECTION");

      if (!ip) {
        debugLog("Invalid IP address. Connection closed.");
        stats.increaseCounter("SMB_INVALID_IP");
        socket.destroy();
        return;
      }

      socket.on("error", (err) => {
        stats.increaseCounter("SMB_ERROR");
        stats.addErrorMessage("SMB#" + err.message);
        debugLog(`Socket error from ${ip}: ${err.message}`);
      });

      honeypotServer.attacker.add(ip, config.banDurationMs);

      // We'll not immediately write a "banner" — we respond properly when a client sends data.
      // But to keep old behaviour, you can send the SMB header first (optional)
      // socket.write(SMB_BANNER);

      // Buffer incoming data until we can process a full NetBIOS packet
      let recvBuf = Buffer.alloc(0);

      socket.on("data", (data) => {
        recvBuf = Buffer.concat([recvBuf, data]);
        stats.increaseCounter("SMB_DATA");

        // NetBIOS Session Service header is 4 bytes: [0] = 0x00, [1..3] length (big-endian)
        while (recvBuf.length >= 4) {
          // Read length from bytes 1..3
          const nbLen = recvBuf.readUIntBE(1, 3); // length of SMB payload
          if (recvBuf.length < 4 + nbLen) {
            // wait for full packet
            break;
          }

          // Extract full SMB packet (without NetBIOS header)
          const smbPacket = recvBuf.slice(4, 4 + nbLen);
          handleSmbPacket(socket, ip, smbPacket);

          // Remove processed packet
          recvBuf = recvBuf.slice(4 + nbLen);
        }
      });

      // close after some idle timeout
      const idleTimer = setTimeout(() => {
        socket.destroy();
        debugLog(`Connection from ${ip} has been closed (idle).`);
      }, 32000);

      socket.on("close", () => {
        debugLog(`Connection from ${ip} has been closed (active).`);
        clearTimeout(idleTimer);
      });
    });

    function handleSmbPacket(socket, ip, smbPacket) {
      debugLog(`Data from ${ip}: ${smbPacket.toString("hex")}`);

      // Basic validation: SMB header starts with 0xFF 'SMB'
      if (
        smbPacket.length < 5 ||
        smbPacket[0] !== 0xff ||
        smbPacket[1] !== 0x53 ||
        smbPacket[2] !== 0x4d ||
        smbPacket[3] !== 0x42
      ) {
        debugLog(`Non-SMB packet or truncated from ${ip}`);
        return;
      }

      const command = smbPacket[4]; // command byte
      debugLog(`SMB command: 0x${command.toString(16)}`);

      // SMB_COM_NEGOTIATE (0x72)
      if (command === 0x72) {
        // parse dialect strings in the payload (very simply)
        const dialects = parseSmbDialects(smbPacket);
        debugLog(`Client dialects from ${ip}: ${JSON.stringify(dialects)}`);

        // send negotiate response choosing a dialect (we pick NT LM 0.12 if present)
        const chosenIndex = dialects.findIndex((d) => /NT LM 0.12/i.test(d));
        const chosen =
          chosenIndex >= 0
            ? dialects[chosenIndex]
            : dialects[0] || "NT LM 0.12";

        const resp = buildNegotiateResponse({
          serverName: "webserver2k.test",
          serverOS: "Windows 2000 5.0",
          domain: "WORKGROUP",
          dialect: chosen,
        });

        socket.write(addNetbiosHeader(resp));
        debugLog(`Sent negotiate response to ${ip} (dialect=${chosen})`);
        return;
      }

      // SMB_COM_SESSION_SETUP_ANDX (0x73)
      if (command === 0x73) {
        const info = parseSessionSetupStrings(smbPacket);
        debugLog(`SessionSetup strings from ${ip}: ${JSON.stringify(info)}`);

        const resp = buildSessionSetupResponse({
          userSessionId: 0x4000, // example UID or TID
          serverOS: "Windows 2000 5.0",
          user: info.username || "",
          nativeOs: "Windows 2000 5.0",
        });

        socket.write(addNetbiosHeader(resp));
        debugLog(`Sent session setup response to ${ip}`);
        return;
      }

      // For other commands, send a generic "not implemented" style response that looks plausible:
      const genericResp = buildGenericErrorResponse(command);
      socket.write(addNetbiosHeader(genericResp));
      debugLog(
        `Sent generic response for cmd 0x${command.toString(16)} to ${ip}`,
      );
    }
  }

  listen() {
    this.#server
      .listen(this.#config.port, this.#config.host, () => {
        debugLog(
          `Honeypot is listening on port ${this.#config.host}:${this.#config.port}`,
        );
      })
      .on("error", (err) => {
        debugLog(`Error: ${err.message}`);
      });
  }
}

// Add 4-byte NetBIOS Session Service header (0x00 + 3-byte big-endian length)
function addNetbiosHeader(smbBuf) {
  const out = Buffer.alloc(4 + smbBuf.length);
  out[0] = 0x00;
  out.writeUIntBE(smbBuf.length, 1, 3);
  smbBuf.copy(out, 4);
  return out;
}

// Very simple dialect parser: looks for ASCII strings in the payload that look like dialects.
// This is forgiving; SMB dialects often come after a byte 0x02 prefix per dialect.
function parseSmbDialects(smbPacket) {
  // find bytes after the SMB header (offset 32 is often where variable bytes start)
  const payload = smbPacket.slice(32);
  const dialects = [];
  let i = 0;
  while (i < payload.length) {
    const b = payload[i];
    if (b === 0x02) {
      // dialect string length prefix in many SMB negotiate requests
      // read until 0x00
      let j = i + 1;
      while (j < payload.length && payload[j] !== 0x00) j++;
      const s = payload.slice(i + 1, j).toString("ascii");
      dialects.push(s);
      i = j + 1;
    } else {
      // fallback: scan for ASCII substrings separated by 0x00
      const z = payload.indexOf(0x00, i);
      if (z === -1) break;
      const s2 = payload.slice(i, z).toString("ascii");
      if (s2.length > 0) dialects.push(s2);
      i = z + 1;
    }
  }
  return dialects;
}

function parseSessionSetupStrings(smbPacket) {
  // naive extraction: search for two UTF-16LE NUL-terminated strings in payload
  const payload = smbPacket.slice(32);
  // try find any UTF-16LE-looking substrings
  // We'll look for common ASCII sequences in UTF-16LE
  const txt = payload.toString("utf16le").replace(/\0+$/, "");
  // split by double null
  const parts = txt.split("\u0000");
  // return some guesses
  return {
    username: parts[0] || "",
    workstation: parts[1] || "",
    nativeLanMan: parts[2] || "",
  };
}

// Build a minimal negotiate response (SMB1). This is a *simplified* fixed response.
// It includes SMB header (ff 'SMB' 0x72) and a small set of fields + strings.
// This is intentionally minimal but plausible.
function buildNegotiateResponse({
  serverName = "webserver2k.test",
  serverOS = "Windows 2000 5.0",
  domain = "",
  dialect = "NT LM 0.12",
} = {}) {
  // This is a small handcrafted SMB1 NEGOTIATE_RESPONSE packet.
  // For robustness you'd craft each field carefully; this is a reasonable emulation blob.
  const serverNameBuf = Buffer.from(serverName + "\u0000", "ascii");
  const serverOsBuf = Buffer.from(serverOS + "\u0000", "ascii");
  const domainBuf = Buffer.from(domain + "\u0000", "ascii");

  // We'll create a very small response body — note sizes/offsets are simplified.
  const header = Buffer.from([
    0xff,
    0x53,
    0x4d,
    0x42, // 'SMB'
    0x72, // command = NEGOTIATE
    0x00,
    0x00,
    0x00,
    0x00, // status
    0x18, // flags (just an example)
    0x01,
    0x28, // flags2 (keep small)
    0x00,
    0x00, // PIDHigh
    0x00,
    0x00,
    0x00,
    0x00, // security features
    0x00,
    0x00, // reserved
    0x00,
    0x00, // TID
    0x00,
    0x00, // PIDLow
    0x00,
    0x00, // UID
    0x00,
    0x00, // MID
  ]);

  // Build body fields: dialect index (2 bytes) + server OS + server name...
  const body = Buffer.concat([
    Buffer.from([0x11]), // Word count (fake/small)
    Buffer.from([0x00]), // filler
    Buffer.from([0x00, 0x00]), // Byte count placeholder (we don't strictly enforce)
    serverOsBuf,
    domainBuf,
    serverNameBuf,
  ]);

  return Buffer.concat([header, body]);
}

function buildSessionSetupResponse({
  userSessionId = 0x4000,
  serverOS = "Windows 2000 5.0",
  user = "",
} = {}) {
  const header = Buffer.from([
    0xff,
    0x53,
    0x4d,
    0x42,
    0x73, // command: SESSION_SETUP_ANDX
    0x00,
    0x00,
    0x00,
    0x00, // status
    0x18, // flags
    0x01,
    0x20, // flags2
    0x00,
    0x00, // PIDHigh
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00, // TID
    0x00,
    0x00, // PIDLow
    (userSessionId >> 8) & 0xff,
    userSessionId & 0xff, // UID (example)
    0x00,
    0x00, // MID
  ]);

  const body = Buffer.from([0x04, 0xff, 0x00, 0x00]); // minimal payload
  const osBuf = Buffer.from(serverOS + "\u0000", "ascii");
  return Buffer.concat([header, body, osBuf]);
}

function buildGenericErrorResponse(command) {
  // Simple SMB error-like response
  const header = Buffer.from([
    0xff,
    0x53,
    0x4d,
    0x42,
    command, // echo same command back
    0x01,
    0x02,
    0x03,
    0x04, // non-zero status (fake) or zero to indicate success
    0x18,
    0x01,
    0x28,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
  ]);
  const body = Buffer.from([0x00]); // minimal
  return Buffer.concat([header, body]);
}
