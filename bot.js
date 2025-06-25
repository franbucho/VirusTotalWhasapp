const { Client, LocalAuth } = require('whatsapp-web.js');
const qrcode = require('qrcode-terminal');
const axios = require('axios');
const FormData = require('form-data');
const fs = require('fs');
const path = require('path');

// Configuración
const VIRUSTOTAL_API_KEY = '2063838b3b3f8b6fe796203c289b68621b849db1bfdb525b5389249e4c9db469';
const MAX_FILE_SIZE_MB = 32;
const ACTIVATION_WORDS = ['revisar', 'scan', 'analizar', 'check', 'review', 'escanear'];

// Inicializar cliente de WhatsApp
const client = new Client({
    authStrategy: new LocalAuth(),
    puppeteer: { 
        headless: true,
        args: ['--no-sandbox', '--disable-setuid-sandbox']
    }
});

// Función para escanear archivos (se mantiene igual)
async function scanFile(filePath) {
    // ... (código existente de scanFile)
}

client.on('qr', qr => {
    qrcode.generate(qr, { small: true });
});

client.on('ready', () => {
    console.log('Client is ready!');
});

client.on('message', async msg => {
    // Verificar si el mensaje contiene palabra clave
    const hasActivationWord = ACTIVATION_WORDS.some(word => 
        msg.body.toLowerCase().includes(word.toLowerCase())
    );

    // Solo responder si tiene archivo Y palabra clave
    if (msg.hasMedia && hasActivationWord) {
        try {
            await msg.reply('🔍 Analizando archivo, por favor espera...');
            
            const media = await msg.downloadMedia();
            const filePath = path.join(__dirname, 'temp_files', `${Date.now()}_${msg.id.id}.tmp`);
            
            if (!fs.existsSync(path.dirname(filePath))) {
                fs.mkdirSync(path.dirname(filePath), { recursive: true });
            }
            
            fs.writeFileSync(filePath, Buffer.from(media.data, 'base64'));
            
            const result = await scanFile(filePath);
            
            let response = `*Resultados del análisis:*\n`;
            response += `🛡️ Motores de antivirus: ${result.totalEngines}\n`;
            response += `☠️ Detectado como malicioso por: ${result.malicious} motores\n\n`;
            response += `📊 Estadísticas:\n`;
            response += `✅ No detectado: ${result.stats.undetected || 0}\n`;
            response += `⚠️ Sospechoso: ${result.stats.suspicious || 0}\n`;
            response += `❌ Malicioso: ${result.stats.malicious || 0}\n\n`;
            response += `🔗 Enlace al análisis completo: ${result.permalink}`;
            
            await msg.reply(response);
            
            fs.unlinkSync(filePath);
        } catch (error) {
            console.error('Error al procesar el archivo:', error);
            await msg.reply(`❌ Error al analizar el archivo: ${error.message}`);
        }
    }
    // No hacer nada en otros casos (mensajes sin palabras clave)
});

client.initialize();