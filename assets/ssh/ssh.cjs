// **BEFORE RUNNING THIS SCRIPT:**
//   1. The server portion is best run on non-Windows systems because they have
//      terminfo databases which are needed to properly work with different
//      terminal types of client connections
//   2. Install `blessed`: `npm install blessed`
//   3. Create a server host key in this same directory and name it `host.key`
// ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null user@127.0.0.1 -p 123
"use strict";

const { generateKeyPairSync } = require("crypto");
const { Server } = require("ssh2");

const hostname =
  "vps-" +
  Math.floor(Math.random() * 0xffffffff)
    .toString(16)
    .padStart(8, "0");
const { privateKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  privateKeyEncoding: {
    type: "pkcs1",
    format: "pem",
  },
  publicKeyEncoding: {
    type: "spki",
    format: "pem",
  },
});

new Server(
  {
    hostKeys: [privateKey],
  },
  (client) => {
    const clientAddr =
      client._sock.remoteAddress + ":" + client._sock.remotePort;
    let authAttempts = 0;

    client
      .on("authentication", (ctx) => {
        authAttempts += 1;
        const method = ctx.method;
        console.log(
          `AUTH attempt #${authAttempts} method=${method} username=${ctx.username}`,
        );

        // When a client connects and sends AUTH method=none, your server should:
        // Reject the attempt (USERAUTH_FAILURE) and Tell the client which methods are allowed (e.g. password, publickey),
        if (ctx.method === "none") {
          return ctx.reject(["password", "publickey", "keyboard-interactive"]);
        }

        // Log credentials depending on method
        if (method === "password") {
          console.log(` -> password supplied: "${ctx.password}"`);
          return Math.random() < 0.6 ? ctx.accept() : ctx.reject();
        }

        if (method === "keyboard-interactive") {
          ctx.prompt([{ prompt: "Password: ", echo: false }], (answers) => {
            console.log(
              ` -> keyboard-interactive answers for ${ctx.username}: ${answers}`,
            );
            setTimeout(
              () => {
                if (Math.random() < 0.4) {
                  ctx.accept();
                } else {
                  ctx.reject();
                }
              },
              500 + Math.random() * 3000,
            );
          });
          return;
        }

        if (method === "publickey") {
          // Public key auth: log key details
          try {
            const pk =
              ctx.key && ctx.key.data
                ? ctx.key.data.toString("base64")
                : "<no-key-data>";
            console.log(
              ` -> publickey algo=${ctx.key?.algo} blob(base64)=${pk} signature=${ctx.signature?.toString("hex")}`,
            );
          } catch (e) {
            console.log(" -> publickey logging error", e);
          }
          // accept so attackers get a shell (if you want realism you can reject if signature missing)
          setTimeout(
            () => {
              try {
                ctx.accept();
              } catch (err) {
                console.error("ctx.accept() failed:", err);
              }
            },
            500 + Math.random() * 1000,
          );
          return;
        }

        // fallback: accept but log
        console.log(
          ` -> unknown auth method "${method}" — accepting for logging`,
        );
        return ctx.reject();
      })
      .on("ready", () => {
        console.log("Client authenticated (ready):", clientAddr);

        client.on("session", (accept, reject) => {
          const session = accept();
          session.on("pty", (acceptPty, rejectPty, info) => {
            console.log(
              "PTY requested from",
              clientAddr,
              "info=",
              JSON.stringify(info),
            );
            acceptPty && acceptPty();
          });

          session.on("window-change", (accept, reject, info) => {
            console.log(
              "Window-Change requested from",
              clientAddr,
              "info=",
              JSON.stringify(info),
            );
            accept && accept();
          });

          session.on("env", (accept, reject, info) => {
            console.log(
              "env requested from",
              clientAddr,
              "info=",
              JSON.stringify(info),
            );
            accept && accept();
          });

          session.on("shell", (acceptShell) => {
            const stream = acceptShell();
            console.log("Shell started for", clientAddr);

            // show motd + prompt
            stream.write("Ubuntu 20.04.6 LTS\r\n");
            stream.write("Welcome to Ubuntu\r\n\n");
            stream.write(
              "Last login: " +
                new Date().toString() +
                " from " +
                clientAddr +
                "\r\n",
            );

            writePrompt(stream);

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
                  writePrompt(stream);
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
                  console.log(`CMD from ${clientAddr}: ${cmd}`);
                  handleFakeCommand(cmd, stream, clientAddr);
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
              console.log("Shell closed for", clientAddr);
            });
            stream.on("error", (err) => {
              console.log("Shell err", err.message);
            });
          });

          session.on("exec", (acceptExec, rejectExec, info) => {
            const stream = acceptExec();
            console.log(
              "Exec request from",
              clientAddr,
              "command=",
              info.command,
            );
            // Emulate execution with canned outputs, delay to look realistic
            emulateExec(info.command, stream, clientAddr);
          });

          session.on("sftp", (acceptSftp, rejectSftp) => {
            console.log(
              "SFTP request from",
              clientAddr,
              " - rejecting (not implemented)",
            );
            // reject to appear like server without SFTP or limited SFTP
            rejectSftp && rejectSftp();
          });
        });
      })
      .on("close", () => {
        console.log("Client disconnected");
      })
      .on("end", () => {
        console.log("Client end");
      })
      .on("error", (err) => {
        console.log("ERROR: " + err.message);
        console.error(err.stack);
      });
  },
).listen(0, function () {
  console.log("Listening on port " + this.address().port);
});

function writePrompt(stream) {
  stream.write(`ubuntu@${hostname}:~$ `);
}

function handleFakeCommand(cmd, stream, clientAddr) {
  // small set of believable responses
  if (!cmd) {
    // empty enter
    writePrompt(stream);
    return;
  }

  const lower = cmd.toLowerCase();
  if (lower === "whoami") {
    stream.write("ubuntu\r\n");
    writePrompt(stream);
    return;
  }
  if (lower === "hostname") {
    stream.write(`${hostname}\r\n`);
    writePrompt(stream);
    return;
  }
  if (lower === "uname") {
    stream.write(`Linux\r\n`);
    writePrompt(stream);
    return;
  }
  if (lower === "uname -a") {
    stream.write(
      `Linux ${hostname} 6.14.0-35-generic #35-Ubuntu SMP PREEMPT_DYNAMIC Sat Oct 10 01:02:31 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux\r\n`,
    );
    writePrompt(stream);
    return;
  }
  if (lower === "ls /") {
    stream.write(
      "bin  boot  dev  etc  home  lib  lib64  lost+found  media  mnt  opt  proc  root  run  sbin  snap  srv  sys  tmp  usr  var\r\n",
    );
    writePrompt(stream);
    return;
  }
  if (lower.startsWith("ls")) {
    stream.write("README.txt  logs  captures\r\n");
    writePrompt(stream);
    return;
  }
  if (lower.startsWith("cat ")) {
    stream.write("Permission denied\r\n");
    writePrompt(stream);
    return;
  }
  if (lower.startsWith("sudo ")) {
    stream.write("Permission denied\r\n");
    writePrompt(stream);
    return;
  }
  if (lower.startsWith("su ")) {
    stream.write("Permission denied\r\n");
    writePrompt(stream);
    return;
  }
  if (lower === "exit" || lower === "logout") {
    stream.write("logout\r\n");
    stream.end();
    return;
  }

  // Unknown commands: pretend /bin/sh returns "command not found"
  setTimeout(
    () => {
      stream.write(`${cmd}: command not found\r\n`);
      writePrompt(stream);
    },
    200 + Math.floor(Math.random() * 750),
  ); // small random delay
}

function emulateExec(command, stream, clientAddr) {
  // mimic command running: small delays + canned output
  console.log(`Emulating exec ${clientAddr}: ${command}`);
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
