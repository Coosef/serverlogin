// n8n Code Node - Telegram Mesaj Formatı
// Kullanıcı Aktivite İzleme Sistemi için
// Tüm event tiplerini destekler (Linux & Windows)

// INPUT: Webhook node'dan gelen body
const body = $json.body || {};

// Telegram MarkdownV2 için kaçış fonksiyonu
function esc(text) {
  if (text === null || text === undefined) return "";
  return text.toString().replace(/([_*\[\]()~`>#+\-=|{}.!\\])/g, "\\$1");
}

// Alert ID üretimi: YYYYMMDDHHMMSS-servername
const ts = body.timestamp || new Date().toISOString();
const d = new Date(ts);

const pad = (n) => n.toString().padStart(2, "0");

const cleanServerName = (body.server_name || "srv")
  .toString()
  .replace(/[^A-Za-z0-9]/g, "")
  .toLowerCase();

const alertId =
  d.getUTCFullYear().toString() +
  pad(d.getUTCMonth() + 1) +
  pad(d.getUTCDate()) +
  pad(d.getUTCHours()) +
  pad(d.getUTCMinutes()) +
  pad(d.getUTCSeconds()) +
  "-" +
  cleanServerName;

// Event tipine göre emoji ve durum metni
function getEventInfo(eventType) {
  const eventMap = {
    // SSH Events
    "ssh_invalid_user": { emoji: "❌", text: "Geçersiz Kullanıcı Denemesi", critical: true },
    "ssh_failed_login": { emoji: "❌", text: "Başarısız SSH Girişi", critical: true },
    "ssh_success_login": { emoji: "✅", text: "Başarılı SSH Girişi", critical: false },
    "ssh_logout": { emoji: "👋", text: "SSH Çıkışı", critical: false },
    
    // Linux Events
    "sudo_command": { emoji: "🔐", text: "Sudo Komutu", critical: true },
    "sudo_failed": { emoji: "⚠️", text: "Sudo Başarısız", critical: true },
    "session_opened": { emoji: "🔓", text: "SSH Session Açıldı", critical: false },
    "session_closed": { emoji: "🔒", text: "SSH Session Kapandı", critical: false },
    "sftp_session_opened": { emoji: "📤", text: "SFTP Bağlantısı Açıldı", critical: false },
    "sftp_session_closed": { emoji: "📥", text: "SFTP Bağlantısı Kapandı", critical: false },
    "sftp_connection": { emoji: "📁", text: "SFTP Bağlantısı", critical: false },
    "ssh_connection": { emoji: "🔌", text: "SSH Bağlantı İsteği", critical: false },
    
    // Windows Events
    "logon_success": { emoji: "✅", text: "Windows Girişi", critical: false },
    "logon_failed": { emoji: "❌", text: "Windows Giriş Başarısız", critical: true },
    "logoff": { emoji: "👋", text: "Windows Çıkışı", critical: false },
    "process_create": { emoji: "⚙️", text: "Process Oluşturuldu", critical: false },
    "file_access": { emoji: "📁", text: "Dosya Erişimi", critical: false },
  };
  
  return eventMap[eventType] || { emoji: "ℹ️", text: eventType || "Bilinmeyen Event", critical: false };
}

const eventInfo = getEventInfo(body.event_type);
const statusText = eventInfo.critical ? "🚨 Kritik" : "ℹ️ Bilgi";

// Mesaj satırlarını hazırla
const lines = [];

// Başlık
lines.push(esc("🚨 Kullanıcı Aktivite Olayı"));
lines.push(esc("ID: " + alertId));
lines.push("");

// Sunucu Bilgileri
const serverName = body.server_name || "Bilinmeyen Sunucu";
const serverIP = body.server_ip || "-";
lines.push(esc("🖥 Sunucu: " + serverName + " (" + serverIP + ")"));
if (body.server_env) {
  lines.push(esc("🌍 Ortam: " + body.server_env));
}
lines.push("");

// Event Bilgileri
lines.push(esc(eventInfo.emoji + " Event: " + eventInfo.text));
lines.push(esc("📊 Tip: " + (body.event_type || "-")));
lines.push(esc("📌 Durum: " + statusText));
lines.push("");

// Kullanıcı Bilgileri
if (body.user) {
  lines.push(esc("👤 Kullanıcı: " + body.user));
}

// Bağlantı Türü (SFTP/SSH)
if (body.connection_type) {
  const connEmoji = body.connection_type === "SFTP" ? "📁" : "🔌";
  lines.push(esc(connEmoji + " Bağlantı Türü: " + body.connection_type));
}

// IP ve Port Bilgileri
if (body.ip) {
  lines.push(esc("🌐 Kaynak IP: " + body.ip));
}
if (body.port) {
  lines.push(esc("🔌 Port: " + body.port));
}

// SFTP Subsystem
if (body.subsystem) {
  lines.push(esc("📦 Subsystem: " + body.subsystem));
}

// Sudo Komut Bilgisi (Linux)
if (body.event_type === "sudo_command" && body.command) {
  lines.push("");
  lines.push(esc("💻 Sudo Komutu:"));
  lines.push(esc("   " + body.command));
  if (body.target_user) {
    lines.push(esc("   → Hedef Kullanıcı: " + body.target_user));
  }
}

// Process Bilgisi (Windows)
if (body.event_type === "process_create" && body.process_name) {
  lines.push("");
  lines.push(esc("⚙️ Process: " + body.process_name));
  if (body.command_line) {
    lines.push(esc("   Komut: " + body.command_line.substring(0, 100) + (body.command_line.length > 100 ? "..." : "")));
  }
}

// Dosya Erişimi (Windows)
if (body.event_type === "file_access" && body.file_path) {
  lines.push("");
  lines.push(esc("📁 Dosya: " + body.file_path));
}

// Güvenlik Bilgileri (SSH başarısız girişler için)
if (body.fail_count_window != null || body.ban_triggered != null) {
  lines.push("");
  lines.push(esc("🔒 Güvenlik Bilgileri:"));
  if (body.time_window_sec) {
    lines.push(esc("   ⏱ Zaman Penceresi: " + body.time_window_sec + " saniye"));
  }
  if (body.fail_count_window != null) {
    lines.push(esc("   ➜ Son " + (body.time_window_sec || 120) + " sn içinde deneme: " + body.fail_count_window));
  }
  if (body.ban_triggered != null) {
    const banText = body.ban_triggered ? "✅ Evet (IP banlandı)" : "❌ Hayır";
    lines.push(esc("   ➜ Ban Durumu: " + banText));
  }
}

// Zaman Bilgisi
lines.push("");
lines.push(esc("📅 Zaman (UTC): " + ts));

// Raw Log
if (body.raw_log) {
  lines.push("");
  lines.push(esc("🧾 Ham Log:"));
  // Log çok uzunsa kısalt
  const rawLog = body.raw_log.length > 200 
    ? body.raw_log.substring(0, 200) + "..." 
    : body.raw_log;
  lines.push(esc(rawLog));
}

// Tek string haline getir
const message = lines.join("\n");

return {
  json: {
    message,
    // Opsiyonel: Telegram'a gönderilecek ekstra bilgiler
    chat_id: "", // Telegram chat ID (n8n'de ayrıca ayarlanabilir)
    parse_mode: "MarkdownV2",
  },
};

