import debug from "debug";
const debugLog = debug("SSHFakeCommands");

export class FakeCommandHandler {
  constructor(stream) {
    this.stream = stream;
    this.hostname =
      "vps-" +
      Math.floor(Math.random() * 0xffffffff)
        .toString(16)
        .padStart(8, "0");
    debugLog(`Initialized with hostname=${this.hostname}`);
  }

  writePrompt() {
    this.stream.write(`ubuntu@${this.hostname}:~$ `);
  }

  handle(cmd) {
    // small set of believable responses
    if (!cmd) {
      this.writePrompt(this.stream);
      return;
    }

    const lower = cmd.toLowerCase();
    debugLog(`Handling command: ${cmd}`);

    if (lower === "whoami") {
      this.stream.write("ubuntu\r\n");
      this.writePrompt(this.stream);
      return;
    }
    if (lower === "hostname") {
      this.stream.write(`${this.hostname}\r\n`);
      this.writePrompt(this.stream);
      return;
    }
    if (lower === "uname") {
      this.stream.write(`Linux\r\n`);
      this.writePrompt(this.stream);
      return;
    }
    if (lower === "uname -a") {
      this.stream.write(
        `Linux ${this.hostname} 6.14.0-35-generic #35-Ubuntu SMP PREEMPT_DYNAMIC Sat Oct 10 01:02:31 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux\r\n`,
      );
      this.writePrompt(this.stream);
      return;
    }
    if (lower === "ls /") {
      this.stream.write(
        "bin  boot  dev  etc  home  lib  lib64  lost+found  media  mnt  opt  proc  root  run  sbin  snap  srv  sys  tmp  usr  var\r\n",
      );
      this.writePrompt(this.stream);
      return;
    }
    if (lower.startsWith("ls")) {
      this.stream.write("README.txt  logs  captures\r\n");
      this.writePrompt(this.stream);
      return;
    }
    if (lower.startsWith("cat ")) {
      this.stream.write("Permission denied\r\n");
      this.writePrompt(this.stream);
      return;
    }
    if (lower.startsWith("sudo ")) {
      this.stream.write("Permission denied\r\n");
      this.writePrompt(this.stream);
      return;
    }
    if (lower.startsWith("su ")) {
      this.stream.write("Permission denied\r\n");
      this.writePrompt(this.stream);
      return;
    }
    if (lower === "exit" || lower === "logout") {
      this.stream.write("logout\r\n");
      this.stream.end();
      return;
    }

    // Unknown commands: pretend /bin/sh returns "command not found"
    setTimeout(
      () => {
        this.stream.write(`${cmd}: command not found\r\n`);
        this.writePrompt(this.stream);
      },
      200 + Math.floor(Math.random() * 750),
    );
  }
}

export function emulateExec(command, stream, clientAddr) {
  // mimic command running: small delays + canned output
  debugLog(`Emulating exec ${clientAddr}: ${command}`);
  if (command === "id") {
    setTimeout(() => {
      stream.write("uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu)\n");
      stream.exit(0);
      stream.end();
    }, 300);
    return;
  }

  // default: pretend not found
  setTimeout(
    () => {
      stream.stderr.write(`sh: ${command}: command not found\n`);
      stream.exit(127);
      stream.end();
    },
    500 + Math.floor(Math.random() * 700),
  );
}
