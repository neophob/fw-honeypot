import debug from "debug";
const debugLog = debug("SMBParser");

export function handleSmbPacket(socket, ip, smbPacket) {
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
      chosenIndex >= 0 ? dialects[chosenIndex] : dialects[0] || "NT LM 0.12";

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
    //2025-11-08T21:06:15.695Z SMBParser SessionSetup strings from 1.2.3.4: {"username":"－蠀Ѐ਑","workstation":"","nativeLanMan":""}
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

  // SMB_COM_TREE_CONNECT_ANDX (0x75)
  if (command === 0x75) {
    const req = parseTreeConnectRequest(smbPacket);
    debugLog(`TreeConnect request from ${ip}: ${JSON.stringify(req)}`);

    // Extract UID from incoming header to reflect same session
    const uid = smbPacket.readUInt16LE(28) || 0x0000;
    const tid = 0x0001; // assign a TID for the tree connect (example)

    const resp = buildTreeConnectResponse({ uid, tid });
    socket.write(addNetbiosHeader(resp));
    debugLog(
      `Sent tree connect response to ${ip} (path=${req.path}, tid=${tid})`,
    );
    return;
  }

  // SMB_COM_TRANSACTION (0x25)
  if (command === 0x25) {
    // Very small, plausible transaction response: success, no payload.
    debugLog(`Transaction request from ${ip}`);
    const resp = buildTransactionResponse({ incoming: smbPacket });
    socket.write(addNetbiosHeader(resp));
    debugLog(`Sent transaction response for cmd 0x25 to ${ip}`);
    return;
  }

  // SMB_COM_NT_CREATE_ANDX (commonly seen as 0x32 in some logs)
  if (command === 0x32) {
    // Provide a minimal NT Create AndX response: return a FID and mirror UID.
    debugLog(`NT Create/AndX (0x32) request from ${ip}`);
    const uid = smbPacket.length >= 29 ? smbPacket.readUInt16LE(28) : 0x0000;
    const fid = 0x0042; // arbitrary file id assigned by honeypot
    const resp = buildNtCreateAndXResponse({ uid, fid });
    socket.write(addNetbiosHeader(resp));
    debugLog(
      `Sent NT Create AndX response (fid=0x${fid.toString(16)}) to ${ip}`,
    );
    return;
  }

  // For other commands, send a generic "not implemented" style response that looks plausible:
  const genericResp = buildGenericErrorResponse(command);
  socket.write(addNetbiosHeader(genericResp));
  debugLog(`Sent generic response for cmd 0x${command.toString(16)} to ${ip}`);
}

// Add 4-byte NetBIOS Session Service header (0x00 + 3-byte big-endian length)
function addNetbiosHeader(smbBuf) {
  const out = Buffer.alloc(4 + smbBuf.length);
  out[0] = 0x00;
  out.writeUIntBE(smbBuf.length, 1, 3);
  smbBuf.copy(out, 4);
  return out;
}

function parseSmbDialects(smbPacket) {
  const wordCount = smbPacket[32] || 0;
  const payload = smbPacket.slice(33 + wordCount); // skip header + wordCount
  const dialects = [];
  let i = 0;

  while (i < payload.length) {
    if (payload[i] === 0x02) {
      let j = i + 1;
      while (j < payload.length && payload[j] !== 0x00) j++;
      dialects.push(payload.slice(i + 1, j).toString("ascii"));
      i = j + 1;
    } else {
      const z = payload.indexOf(0x00, i);
      if (z === -1) break;
      const s = payload.slice(i, z).toString("ascii");
      if (s.length) dialects.push(s);
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

function buildNegotiateResponse({
  serverName = "webserver2k.test",
  serverOS = "Windows 2000 5.0",
  domain = "WORKGROUP",
  dialect = "NT LM 0.12",
} = {}) {
  const serverNameBuf = Buffer.from(serverName + "\0", "ascii");
  const serverOsBuf = Buffer.from(serverOS + "\0", "ascii");
  const domainBuf = Buffer.from(domain + "\0", "ascii");

  // SMB Header 32 bytes
  const header = Buffer.alloc(32);
  header[0] = 0xff;
  header[1] = 0x53;
  header[2] = 0x4d;
  header[3] = 0x42; // 'SMB'
  header[4] = 0x72; // command = NEGOTIATE
  // Status (5-8) = 0
  header[9] = 0x18; // Flags
  header.writeUInt16LE(0x2801, 10); // Flags2 NT LM 0.12 + Unicode support
  // TID (24-25), PIDLow (26-27), UID (28-29), MID (30-31) all zero for minimal response

  // Body
  const wordCount = Buffer.from([0x01]); // WordCount = 1 (DialectIndex)
  const dialectIndex = Buffer.from([0x00, 0x00]); // first dialect
  const byteCount = Buffer.alloc(2); // will fill later

  const stringsBuf = Buffer.concat([serverOsBuf, domainBuf, serverNameBuf]);
  byteCount.writeUInt16LE(stringsBuf.length, 0);

  const body = Buffer.concat([wordCount, dialectIndex, byteCount, stringsBuf]);
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

/**
 * Parse a Tree Connect AndX request to extract the UNC path (e.g. \\host\share)
 * Returns an object: { path: string|null, service: string|null, unicode: boolean }
 * This is forgiving and works with common client encodings.
 */
function parseTreeConnectRequest(smbPacket) {
  const payload = smbPacket.slice(32);
  const flags2 = smbPacket.length >= 12 ? smbPacket.readUInt16LE(10) : 0;
  const unicode = !!(flags2 & 0x8000);

  let path = null;
  let service = null;

  if (unicode) {
    // try to find a UTF-16LE backslash sequence (\\)
    const txt = payload.toString("utf16le").replace(/\0+$/, "");
    // find first occurrence of \\\\ (two backslashes)
    const idx = txt.indexOf("\\\\");
    if (idx !== -1) {
      // path likely continues until a NUL or until next 0x02 separator
      const parts = txt.slice(idx).split("\u0000");
      path = parts[0] || null;
      // sometimes service follows after a separator (0x02) or next string
      if (parts.length > 1) service = parts[1] || null;
    } else {
      // fallback: any utf16le printable run that contains backslash
      const re = /(\\{2}[^\\\u0000]*)/;
      const m = txt?.match(re);
      if (m) path = m[1];
    }
  } else {
    // ASCII/OEM path
    const txt = payload.toString("ascii").replace(/\0+$/, "");
    const idx = txt.indexOf("\\\\");
    if (idx !== -1) {
      const parts = txt.slice(idx).split("\0");
      path = parts[0] || null;
      if (parts.length > 1) service = parts[1] || null;
    } else {
      // try a conservative substring search
      const m = txt?.match(/(\\\\[^\0]+)/);
      if (m) path = m[1];
    }
  }

  return { path, service, unicode };
}

// Minimal plausible Tree Connect Response for SMB1 (command 0x75)
// This keeps the layout simple: 32-byte SMB header, WordCount=3 (6 bytes words), ByteCount=0
function buildTreeConnectResponse({ uid = 0x0000, tid = 0x0001 } = {}) {
  // SMB header 32 bytes
  const header = Buffer.alloc(32, 0);
  header[0] = 0xff;
  header[1] = 0x53;
  header[2] = 0x4d;
  header[3] = 0x42;
  header[4] = 0x75; // TREE_CONNECT_ANDX
  // status (4 bytes) left 0 = success
  header[9] = 0x18; // flags (optional)
  header.writeUInt16LE(0x2801, 10); // flags2 (example)
  // set TID (bytes 24..25) and UID (28..29)
  header.writeUInt16LE(tid & 0xffff, 24);
  header.writeUInt16LE(uid & 0xffff, 28);

  // WordCount (1) + Words (3 * 2 bytes = 6 bytes)
  const wordCount = Buffer.from([0x03]);
  // AndXCommand (1), AndXReserved (1), AndXOffset (2), Optional: ShareType/Access/MaxAccess etc
  // We'll return zeros for words except AndXCommand = 0xff (no further command)
  const words = Buffer.alloc(6, 0);
  words[0] = 0xff; // AndXCommand = NO further
  words[1] = 0x00; // reserved
  // AndXOffset left zero

  // ByteCount = 0 (no data strings)
  const byteCount = Buffer.alloc(2, 0x00);

  return Buffer.concat([header, wordCount, words, byteCount]);
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

// --- New minimal implementations for cmd 0x25 (TRANS) and 0x32 (NT_CREATE_ANDX)

function buildTransactionResponse({ incoming } = {}) {
  // Build a minimal successful transaction response
  // 32-byte header, command 0x25, status 0, some basic flags
  const header = Buffer.alloc(32, 0);
  header[0] = 0xff;
  header[1] = 0x53;
  header[2] = 0x4d;
  header[3] = 0x42;
  header[4] = 0x25; // TRANS
  // status left 0 = success
  header[9] = 0x18; // flags (optional)
  header.writeUInt16LE(0x2801, 10); // flags2

  // Mirror UID from request if present
  if (incoming && incoming.length >= 30) {
    try {
      const uid = incoming.readUInt16LE(28);
      header.writeUInt16LE(uid & 0xffff, 28);
    } catch (e) {
      // ignore
    }
  }

  // Minimal body: WordCount = 0, ByteCount = 0
  const body = Buffer.from([0x00, 0x00, 0x00]);
  // (0x00 = WordCount, followed by 2-byte ByteCount = 0)
  return Buffer.concat([header, body]);
}

function buildNtCreateAndXResponse({ uid = 0x0000, fid = 0x0042 } = {}) {
  // Minimal NT Create AndX response: header + WordCount=1 + FID + ByteCount=0
  const header = Buffer.alloc(32, 0);
  header[0] = 0xff;
  header[1] = 0x53;
  header[2] = 0x4d;
  header[3] = 0x42;
  header[4] = 0x32; // NT Create AndX (logged as 0x32 in user's environment)
  // status bytes 5..8 left zero => success
  header[9] = 0x18; // flags
  header.writeUInt16LE(0x2801, 10); // flags2
  // set UID
  header.writeUInt16LE(uid & 0xffff, 28);

  // WordCount = 1, FID (2 bytes)
  const wordCount = Buffer.from([0x01]);
  const fidBuf = Buffer.alloc(2);
  fidBuf.writeUInt16LE(fid & 0xffff, 0);

  // ByteCount = 0
  const byteCount = Buffer.alloc(2, 0x00);

  return Buffer.concat([header, wordCount, fidBuf, byteCount]);
}
