import https from "https";
import debug from "debug";

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
            parse_mode: "Markdown",
        });

        const options = {
            hostname: "api.telegram.org",
            port: 443,
            path: `/bot${botToken}/sendMessage`,
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Content-Length": data.length,
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
                    resolve();
                } else {
                    debugLog(
                        `Failed to send message to Telegram: ${res.statusCode} - ${responseData}`,
                    );
                    reject(
                        new Error(
                            `Telegram API error: ${res.statusCode} - ${responseData}`,
                        ),
                    );
                }
            });
        });

        req.on("error", (error) => {
            debugLog(`Error sending message to Telegram: ${error.message}`);
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
    const time = new Date().toLocaleString();
    let message = `🚨 *Honeypot Alert* 🚨\n\n`;

    // Add metadata
    if (metadata) {
        message += `📊 *Metadata:*\n`;
        message += `• IP: \`${metadata.ip || "Unknown"}\`\n`;
        message += `• Country: ${metadata.country || "Unknown"}\n`;
        message += `• Service: ${metadata.serviceName || "Unknown"}\n`;
        message += `• Size: ${metadata.size || "Unknown"} bytes\n`;
        message += `• Time: ${time}\n\n`;
    }

    // Add LLM analysis result
    if (llmResult) {
        message += `🤖 *LLM Analysis:*\n`;
        if (llmResult.threadlevel) {
            const threat = llmResult.threadlevel.toString().toUpperCase();
            const emoji = threat === "HIGH" ? "🔴" : threat === "MEDIUM" ? "🟡" : "🟢";
            message += `• Threat Level: ${emoji} ${threat}\n`;
        }
        if (llmResult.summary) {
            message += `• Summary: ${llmResult.summary}\n`;
        }
        if (llmResult.details) {
            message += `• Details: ${llmResult.details}\n`;
        }
        message += `\n`;
    }

    // Add ASCII dump (truncated if too long)
    if (asciiDump) {
        message += `📝 *Data Dump:*\n`;
        const maxDumpLength = 500;
        if (asciiDump.length > maxDumpLength) {
            message += `\`\`\`\n${asciiDump.substring(0, maxDumpLength)}...\n\`\`\`\n`;
            message += `_(Truncated from ${asciiDump.length} characters)_\n`;
        } else {
            message += `\`\`\`\n${asciiDump}\n\`\`\`\n`;
        }
    }

    return message;
}
