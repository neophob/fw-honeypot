import debug from "debug";
const debugLog = debug("SSHFakeCommands");

function generateHostname() {
  return (
    "vps-" +
    Math.floor(Math.random() * 0xffffffff)
      .toString(16)
      .padStart(8, "0")
  );
}

export function runFakeCommand(cmd, hostname) {
  const lower = (cmd || "").toLowerCase().trim();
  const result = {
    stdout: "",
    stderr: "",
    exitCode: 0,
    delay: Math.floor(Math.random() * 500),
  };

  if (!lower) {
    return result;
  }

  switch (lower) {
    case "whoami":
      result.stdout = "ubuntu\n";
      return result;

    case "hostname":
      result.stdout = `${hostname}\n`;
      return result;

    case "pwd":
      result.stdout = "/home/ubuntu\n";
      return result;

    case "uname":
      result.stdout = "Linux\n";
      return result;

    case "uname -a":
      result.stdout =
        `Linux ${hostname} 6.14.0-35-generic #35-Ubuntu SMP PREEMPT_DYNAMIC ` +
        `Sat Oct 10 01:02:31 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux\n`;
      return result;

    case "ls /":
      result.stdout =
        "bin  boot  dev  etc  home  lib  lib64  lost+found  media  mnt  opt  proc  root  run  sbin  snap  srv  sys  tmp  usr  var\n";
      return result;

    case "id":
      result.stdout = "uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu)\n";
      return result;
  }

  // pattern-based commands
  if (lower.startsWith("ls")) {
    result.stdout = ".bash_history  README.txt  logs  captures\n";
    return result;
  }

  if (lower === "cat .bash_history") {
    result.stdout = "curl https://tinyurl.com/nhcuf9ucca\npwd\nls\nll\n";
    return result;
  }

  if (
    lower.startsWith("cat ") ||
    lower.startsWith("sudo ") ||
    lower.startsWith("su ")
  ) {
    result.stderr = "Permission denied\n";
    result.exitCode = 1;
    return result;
  }

  // default: command not found
  result.stderr = `sh: ${cmd}: command not found\n`;
  result.exitCode = 127;
  return result;
}

export class FakeCommandHandler {
  constructor(stream) {
    this.stream = stream;
    this.hostname = generateHostname();
    debugLog(`Initialized with hostname=${this.hostname}`);
  }

  writePrompt() {
    this.stream.write(`ubuntu@${this.hostname}:~$ `);
  }

  handle(cmd) {
    debugLog(`Handling command: ${cmd}`);

    const result = runFakeCommand(cmd, this.hostname);

    setTimeout(() => {
      if (result.stdout) {
        this.stream.write(result.stdout.replace(/\n/g, "\r\n"));
      }
      if (result.stderr) {
        this.stream.write(result.stderr.replace(/\n/g, "\r\n"));
      }

      if (cmd === "exit" || cmd === "logout") {
        this.stream.write("logout\r\n");
        this.stream.end();
        return;
      }

      this.writePrompt();
    }, result.delay);
  }
}

export function emulateExec(command, stream, ip) {
  debugLog(`Emulating exec ${ip}: ${command}`);
  const result = runFakeCommand(command, generateHostname());

  setTimeout(() => {
    if (result.stdout) {
      stream.write(result.stdout);
    }
    if (result.stderr) {
      stream.stderr.write(result.stderr);
    }

    stream.exit(result.exitCode);
    stream.end();
  }, result.delay);
}
