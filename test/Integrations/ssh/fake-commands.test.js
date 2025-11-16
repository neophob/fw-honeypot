import test from "node:test";
import assert from "node:assert/strict";
import {
  FakeCommandHandler,
  emulateExec,
} from "../../../src/Integrations/ssh/fake-commands.js";

class MockStream {
  constructor() {
    this.data = "";
    this.stderrData = "";
    this.ended = false;
    this.exitCode = null;
    this.stderr = {
      write: (chunk) => {
        this.stderrData += chunk;
      },
    };
  }
  write(chunk) {
    this.data += chunk;
  }
  end() {
    this.ended = true;
  }
  exit(code) {
    this.exitCode = code;
  }
  getOutput() {
    return this.data;
  }
  getError() {
    return this.stderrData;
  }
}

test("FakeCommandHandler: should write prompt on initialization", () => {
  // Given
  const stream = new MockStream();
  const handler = new FakeCommandHandler(stream);

  // When
  handler.writePrompt();

  // Then
  assert.match(stream.getOutput(), /ubuntu@vps-[0-9a-f]{8}:~\$/);
});

test("FakeCommandHandler: whoami command returns ubuntu", async () => {
  // Given
  const stream = new MockStream();
  const handler = new FakeCommandHandler(stream);

  // When
  handler.handle("whoami");

  // Wait for the delayed output (max 500ms + a small buffer)
  await new Promise((resolve) => setTimeout(resolve, 550));

  // Then
  const output = stream.getOutput();
  assert(output.includes("ubuntu\r\n"));
  assert.match(output, /ubuntu@vps-[0-9a-f]{8}:~\$/);
});

test("FakeCommandHandler: unknown command returns 'command not found'", async () => {
  const stream = new MockStream();
  const handler = new FakeCommandHandler(stream);

  handler.handle("foobar123");

  // Wait enough time for the delayed command response (max 500ms + buffer)
  await new Promise((resolve) => setTimeout(resolve, 550));

  const output = stream.getOutput();
  assert(output.includes("foobar123: command not found"));
  assert.match(output, /ubuntu@vps-[0-9a-f]{8}:~\$/);
});

test("FakeCommandHandler: exit command ends stream", async () => {
  // Given
  const stream = new MockStream();
  const handler = new FakeCommandHandler(stream);

  // When
  handler.handle("exit");

  // Wait enough time for the delayed command response
  await new Promise((resolve) => setTimeout(resolve, 550));

  // Then
  assert(stream.ended === true);
});

test("emulateExec: id command returns correct output", (t) => {
  // Given
  const stream = new MockStream();

  // When
  emulateExec("id", stream);

  // Then: async wait
  return new Promise((resolve) => {
    setTimeout(() => {
      assert(stream.getOutput().includes("uid=1000(ubuntu)"));
      assert(stream.exitCode === 0);
      assert(stream.ended === true);
      resolve();
    }, 500);
  });
});

test("emulateExec: unknown command returns command not found", (t) => {
  // Given
  const stream = new MockStream();

  // When
  emulateExec("foobar123", stream);

  // Then: async wait
  return new Promise((resolve) => {
    setTimeout(() => {
      assert(stream.stderrData.includes("sh: foobar123: command not found"));
      assert(stream.exitCode === 127);
      assert(stream.ended === true);
      resolve();
    }, 1500);
  });
});
