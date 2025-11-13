import { stats } from "../../utils/statistics.js";
import debug from "debug";
const debugLog = debug("SSHServerAuth");

export function handleServerAuth(ctx, ip, authAttempts) {
  const method = ctx.method;
  debugLog(
    `AUTH attempt #${authAttempts} method=${method} username=${ctx.username}`,
  );

  // When a client connects and sends AUTH method=none, your server should:
  // Reject the attempt (USERAUTH_FAILURE) and Tell the client which methods are allowed (e.g. password, publickey),
  if (method === "none") {
    return ctx.reject(["password", "publickey", "keyboard-interactive"]);
  }

  // Log credentials depending on method
  if (method === "password") {
    debugLog(` -> password supplied: "${ctx.password}"`);
    stats.increaseCounter("SSH_AUTH_PASSWORD");
    return Math.random() < 0.6 ? ctx.accept() : ctx.reject();
  }

  if (method === "keyboard-interactive") {
    ctx.prompt([{ prompt: "Password: ", echo: false }], (answers) => {
      stats.increaseCounter("SSH_AUTH_KEYBOARD_INTERACTIVE");
      debugLog(
        ` -> keyboard-interactive answers for ${ctx.username}: ${answers}`,
      );
      setTimeout(
        () => {
          if (Math.random() < 0.6) {
            debugLog("keyboard-interactive accepted");
            ctx.accept();
          } else {
            debugLog("keyboard-interactive rejected");
            ctx.reject();
          }
        },
        500 + Math.random() * 3000,
      );
    });
    return;
  }

  if (method === "publickey") {
    stats.increaseCounter("SSH_AUTH_PUBLIC_KEY");
    // Public key auth: log key details
    try {
      const pk =
        ctx.key && ctx.key.data
          ? ctx.key.data.toString("base64")
          : "<no-key-data>";
      debugLog(
        ` -> publickey algo=${ctx.key?.algo} blob(base64)=${pk} signature_present=${!!ctx.signature}`,
      );
    } catch (e) {
      debugLog(" -> publickey logging error", e);
    }
    // accept so attackers get a shell (if you want realism you can reject if signature missing)
    setTimeout(
      () => {
        try {
          ctx.accept();
        } catch (err) {
          debugLog("ctx.accept() failed:", err.message);
          stats.addErrorMessage("SSHAuthErr#" + err.message);
        }
      },
      500 + Math.random() * 1000,
    );
    return;
  }

  // fallback: accept but log
  stats.increaseCounter("SSH_AUTH_UNKNOWN");
  debugLog(` -> unknown auth method "${method}" — accepting for logging`);
  return ctx.reject();
}
