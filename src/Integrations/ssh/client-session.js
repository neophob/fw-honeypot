import debug from "debug";
import { FakeCommandHandler, emulateExec } from "./fake-commands.js";
import { stats } from "../../utils/statistics.js";
import { track } from "../../utils/tracker.js";

const SERVICE_NAME = "SSH";
const debugLog = debug("SSHClientSession");

export function handleExec(command, stream, clientAddr) {
  emulateExec(command, stream, clientAddr);
};

export function handleClientSessionSession(acceptShell, ip) {
  const stream = acceptShell();
  const fakeCommandHandler = new FakeCommandHandler(stream);
  debugLog("Shell started for", ip);

  // show motd + prompt
  stream.write("Ubuntu 20.04.6 LTS\r\n");
  stream.write("Welcome to Ubuntu\r\n\n");
  stream.write("Last login: " + new Date().toString() + " from " + ip + "\r\n");

  fakeCommandHandler.writePrompt();
  track(
    ip,
    SERVICE_NAME,
    Buffer.from(", Shell commands executed: ", "utf8").toString("hex"),
  );

  // buffer user input line-by-line
  let cmdBuf = "";
  stream.on("data", (chunk) => {
    const s = chunk.toString("utf8");
    let i = 0;
    while (i < s.length) {
      // Detect arrow up escape sequence: \x1b[A
      if (s[i] === "\x1b" && s[i + 1] === "[" && s[i + 2] === "A") {
        // Ignore arrow up
        i += 3;
        continue;
      }
      const ch = s[i];

      // Ctrl-C (ETX, 0x03) -> cancel current line, show ^C and new prompt
      if (ch === "\x03") {
        stream.write("^C\r\n");
        cmdBuf = "";
        fakeCommandHandler.writePrompt();
        i++;
        continue;
      }

      // Ctrl-D (EOT, 0x04) -> close the shell
      if (ch === "\x04") {
        stream.end();
        return;
      }

      // TAB (0x09) or Ctrl-L — ignore it completely
      if (ch === "\t" || ch === "\x0c") {
        i++;
        continue;
      }

      // Backspace / DEL
      if (ch === "\x7f" || ch === "\b") {
        if (cmdBuf.length > 0) {
          // remove last char from buffer and send backspace sequence to client
          cmdBuf = cmdBuf.slice(0, -1);
          // Move cursor back, erase char, move cursor back (common terminal sequence)
          stream.write("\b \b");
        }
        i++;
        continue;
      }

      // Carriage return or newline: process line
      if (ch === "\r" || ch === "\n") {
        stream.write("\r\n"); // echo newline
        const cmd = cmdBuf.trim();
        debugLog(`CMD from ${ip}: ${cmd}`);
        track(
          ip,
          SERVICE_NAME,
          Buffer.from('"' + cmd + '", ', "utf8").toString("hex"),
        );

        fakeCommandHandler.handle(cmd);
        cmdBuf = "";
        i++;
        continue;
      }

      // Printable character: append to buffer and echo it
      cmdBuf += ch;
      stream.write(ch);
      i++;
    }
  });

  stream.on("close", () => {
    debugLog("Shell closed for", ip);
  });

  stream.on("error", (err) => {
    debugLog("Shell err", err.message);
    stats.increaseCounter("SSH_ERROR");
    stats.addErrorMessage("SSHClientSessionError#" + err.message);
  });
}
