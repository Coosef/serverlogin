// n8n Code Node - Telegram Mesaj Formatı (Kompakt Versiyon)
// Daha kısa ve öz mesajlar için
// Kullanıcı Aktivite İzleme Sistemi için

// INPUT: Webhook node'dan gelen body
const body = $json.body || {};

// Telegram MarkdownV2 için kaçış fonksiyonu
function esc(text) {
  if (text === null || text === undefined) return "";
  return text.toString().replace(/([_*\[\]()~`>#+\-=|{}.!\\])/g, "\\$1");
}

// Event tipine göre emoji
function getEventEmoji(eventType) {
  const emojiMap = {
    "ssh_invalid_user": "❌",
    "ssh_failed_login": "❌",
    "ssh_success_login": "✅",
    "ssh_logout": "👋",
    "sudo_command": "🔐",
    "sudo_failed": "⚠️",
    "session_opened": "🔓",
    "session_closed": "🔒",
    "logon_success": "✅",
    "logon_failed": "❌",
    "logoff": "👋",
    "process_create": "⚙️",
    "file_access": "📁",
  };
  return emojiMap[eventType] || "ℹ️";
}

// Zaman formatı: HH:MM:SS
const ts = body.timestamp || new Date().toISOString();
const d = new Date(ts);
const timeStr = 
  d.getUTCHours().toString().padStart(2, "0") + ":" +
  d.getUTCMinutes().toString().padStart(2, "0") + ":" +
  d.getUTCSeconds().toString().padStart(2, "0");

const emoji = getEventEmoji(body.event_type);
const serverName = body.server_name || "srv";
const userName = body.user || "-";
const ip = body.ip || "-";

// Kompakt mesaj formatı
let message = esc(emoji + " " + (body.event_type || "event"));
message += "\n";
message += esc("🖥 " + serverName);
if (body.server_ip) {
  message += esc(" (" + body.server_ip + ")");
}
message += "\n";
message += esc("👤 " + userName);
if (ip !== "-") {
  message += esc(" | 🌐 " + ip);
}
message += "\n";
message += esc("🕐 " + timeStr + " UTC");

// Ban durumu varsa ekle
if (body.ban_triggered) {
  message += "\n";
  message += esc("🚫 IP banlandı!");
}

// Sudo komutu varsa ekle
if (body.event_type === "sudo_command" && body.command) {
  message += "\n";
  message += esc("💻 " + body.command.substring(0, 50) + (body.command.length > 50 ? "..." : ""));
}

// Process varsa ekle
if (body.event_type === "process_create" && body.process_name) {
  message += "\n";
  message += esc("⚙️ " + body.process_name);
}

return {
  json: {
    message,
    parse_mode: "MarkdownV2",
  },
};

