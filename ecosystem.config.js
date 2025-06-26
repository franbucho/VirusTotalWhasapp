module.exports = {
  apps: [{
    name: "whatsapp-bot",
    script: "bot.js",
    watch: true,
    ignore_watch: ["node_modules", "session_data", "temp"],
    autorestart: true,
    max_memory_restart: "500M"
  }]
}