import https from "https";
import debug from "debug";
import { stats } from "./statistics.js";

const debugLog = debug("TelegramBot");

// use @BotFather to create a bot and get the token

/**
 * Sends a message to a Telegram bot
 * @param {string} botToken - The Telegram bot token (from BotFather)
 * @param {string} chatId - The chat ID to send the message to
 * @param {string} message - The message to send (supports markdown)
 * @returns {Promise<void>}
 */
export async function sendTelegramMessage(botToken, chatId, message) {
  if (!botToken || !chatId) {
    debugLog("Telegram bot token or chat ID not configured, skipping message");
    return;
  }

  // Telegram has a 4096 character limit per message
  const MAX_MESSAGE_LENGTH = 4096;
  let messagesToSend = [];

  if (message.length > MAX_MESSAGE_LENGTH) {
    // Split the message into chunks
    for (let i = 0; i < message.length; i += MAX_MESSAGE_LENGTH) {
      messagesToSend.push(message.substring(i, i + MAX_MESSAGE_LENGTH));
    }
  } else {
    messagesToSend.push(message);
  }

  for (const msg of messagesToSend) {
    await sendSingleMessage(botToken, chatId, msg);
  }
}

/**
 * Sends a single message to Telegram
 * @param {string} botToken - The Telegram bot token
 * @param {string} chatId - The chat ID
 * @param {string} message - The message to send
 * @returns {Promise<void>}
 */
function sendSingleMessage(botToken, chatId, message) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify({
      chat_id: chatId,
      text: message,
      parse_mode: "HTML",
    });

    const options = {
      hostname: "api.telegram.org",
      port: 443,
      path: `/bot${botToken}/sendMessage`,
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(data),
      },
    };

    const req = https.request(options, (res) => {
      let responseData = "";

      res.on("data", (chunk) => {
        responseData += chunk;
      });

      res.on("end", () => {
        if (res.statusCode === 200) {
          debugLog("Message sent successfully to Telegram");
          stats.increaseCounter("TELEGRAM_MESSAGE_SENT");
          resolve();
        } else {
          const errorMsg = `Failed to send message to Telegram: ${res.statusCode} - ${responseData}`;
          debugLog(errorMsg);
          stats.increaseCounter("TELEGRAM_MESSAGE_FAILED");
          stats.addErrorMessage(
            `TELEGRAM-ERROR#${res.statusCode} - ${responseData}`,
          );
          reject(new Error(errorMsg));
        }
      });

      res.on("error", (err) => {
        debugLog(`Error receiving response from Telegram: ${err.message}`);
        stats.increaseCounter("TELEGRAM_RESPONSE_ERROR");
        stats.addErrorMessage(`TELEGRAM-RESPONSE-ERROR#${err.message}`);
        reject(err);
      });
    });

    req.on("error", (error) => {
      debugLog(`Error sending message to Telegram: ${error.message}`);
      stats.increaseCounter("TELEGRAM_REQUEST_ERROR");
      stats.addErrorMessage(`TELEGRAM-REQUEST-ERROR#${error.message}`);
      reject(error);
    });

    req.write(data);
    req.end();
  });
}

/**
 * Formats LLM analysis data for Telegram
 * @param {string} asciiDump - ASCII dump of the data
 * @param {object} metadata - Metadata about the connection
 * @param {object} llmResult - LLM analysis result
 * @returns {string} Formatted message
 */
export function formatLlmDataForTelegram(asciiDump, metadata, llmResult) {
  debugLog(
    `Formatting message - asciiDump length: ${asciiDump?.length || 0}, metadata: ${!!metadata}, llmResult: ${!!llmResult}`,
  );

  const time = new Date().toLocaleString();
  let message = `🚨 <b>Honeypot Alert</b> 🚨\n\n`;

  // Add metadata
  if (metadata) {
    message += `📊 <b>Metadata:</b>\n`;
    message += `• IP: <code>${metadata.sourceIP || "Unknown"}</code>\n`;
    message += `• Country: ${metadata.country || "Unknown"}\n`;
    message += `• Service: ${metadata.service || "Unknown"}\n`;
    message += `• Size: ${metadata.dumpSize || "Unknown"} bytes\n`;
    message += `• Time: ${time}\n\n`;
  }

  // Add LLM analysis result
  if (llmResult) {
    message += `🤖 <b>LLM Analysis:</b>\n`;
    if (llmResult.threadlevel) {
      const threat = llmResult.threadlevel.toString().toUpperCase();
      const emoji = threat === "RED" ? "🔴" : threat === "YELLOW" ? "🟡" : "🟢";
      message += `• Threat Level: ${emoji} ${threat}\n`;
    }
    if (llmResult.analyse) {
      message += `• Summary: ${escapeHtml(llmResult.analyse)}\n`;
    }
    if (llmResult.mitre_phase) {
      message += `• Mitre Phase: ${escapeHtml(llmResult.mitre_phase)}\n`;
    }
    message += `\n`;
  }

  // Add ASCII dump (truncated if too long)
  if (asciiDump) {
    message += `📝 <b>Data Dump:</b>\n`;
    const maxDumpLength = 1300;
    const dumpContent =
      asciiDump.length > maxDumpLength
        ? asciiDump.substring(0, maxDumpLength) + "..."
        : asciiDump;

    // Use <pre> tag for monospaced formatting
    message += `<pre>${escapeHtml(dumpContent)}</pre>\n`;

    if (asciiDump.length > maxDumpLength) {
      message += `<i>(Truncated from ${asciiDump.length} characters)</i>\n`;
    }
  }

  return message;
}

/**
 * Escapes HTML special characters to prevent formatting issues
 * @param {string} text - Text to escape
 * @returns {string} Escaped text
 */
function escapeHtml(text) {
  if (!text) return text;
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}
