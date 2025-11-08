import test from "node:test";
import assert from "node:assert/strict";

import { handleSmbPacket } from "../../../src/Integrations/smb/parser.js";

test("parse SMB Packet SMB_COM_NEGOTIATE", () => {
  // GIVEN
  const data = Buffer.from(
    "ff534d4272000000001801c8000000000000000000000000ffff000000000000002200024e54204c4d20302e31320002534d4220322e3030320002534d4220322e3f3f3f00",
    "hex",
  );

  const socketData = [];
  const socketMock = {
    write: (data) => {
      socketData.push(data);
    },
  };

  // WHEN
  handleSmbPacket(socketMock, "1.2.3.4", data);

  // THEN
  assert.equal(socketData.length, 1);
  assert.equal(socketData[0].length, 80);
  const resultAsString = socketData[0].toString();
  assert.equal(resultAsString.includes("Windows 2000"), true);
  assert.equal(resultAsString.includes("WORKGROUP"), true);
  assert.equal(resultAsString.includes("webserver2k.test"), true);
});

test("parse SMB Packet SMB_COM_SESSION_SETUP_ANDX", () => {
  // GIVEN
  const data = Buffer.from(
    "ff534d4273000000001807c00000000000000000000000000000fffe000040000dff00880004110a000000000000000100000000000000d40000004b000000000000570069006e0064006f007700730020003200300030003000200032003100390035000000570069006e0064006f007700730020003200300030003000200035002e0030000000",
    "hex",
  );

  const socketData = [];
  const socketMock = {
    write: (data) => {
      socketData.push(data);
    },
  };

  // WHEN
  handleSmbPacket(socketMock, "1.2.3.4", data);

  // THEN
  assert.equal(socketData.length, 1);
  assert.equal(socketData[0].length, 53);
  const resultAsString = socketData[0].toString();
  assert.equal(resultAsString.includes("Windows 2000 5."), true);
});

test("parse SMB Packet SMB_COM_TREE_CONNECT_ANDX", () => {
  // GIVEN
  const data = Buffer.from(
    "ff534d4275000000001807c00000000000000000000000000000fffe04ff400004ff005c00080001003100005c005c003100390032002e003100360038002e00350036002e00320030005c00490050004300240000003f3f3f3f3f00",
    "hex",
  );

  const socketData = [];
  const socketMock = {
    write: (data) => {
      socketData.push(data);
    },
  };

  // WHEN
  handleSmbPacket(socketMock, "1.2.3.4", data);

  // THEN
  assert.equal(socketData.length, 1);
  assert.equal(socketData[0].length, 45);
});
