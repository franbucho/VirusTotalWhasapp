const { Client, LocalAuth } = require('whatsapp-web.js');
const qrcode = require('qrcode-terminal');
const axios = require('axios');
const FormData = require('form-data');
const fs = require('fs');
const path = require('path');

// Configuración
const VIRUSTOTAL_API_KEY = '2063838b3b3f8b6fe796203c289b68621b849db1bfdb525b5389249e4c9db469';
const MAX_FILE_SIZE_MB = 32;
const ACTIVATION_WORDS = ['revisar', 'scan', 'analizar', 'check', 'review', 'escanear']; // Palabras clave

// Inicializar cliente de WhatsApp
const client = new Client({
    authStrategy: new LocalAuth(),
    puppeteer: { 
        headless: true,
        args: ['--no-sandbox', '--disable-setuid-sandbox']
    }
});

// Resto del código de scanFile() permanece igual...
async function scanFile(filePath) {
    // ... (el mismo código de scanFile que teníamos antes)
}

// Modificamos el evento 'message' para incluir la verificación de palabras clave
client.on('message', async msg => {
    // Verificar si el mensaje contiene alguna palabra clave (ignorando mayúsculas/minúsculas)
    const hasActivationWord = ACTIVATION_WORDS.some(word => 
        msg.body.toLowerCase().includes(word.toLowerCase())
    );

    if (msg.hasMedia && hasActivationWord) {
        try {
            await msg.reply('🔍 Recibí tu solicitud de análisis, procesando archivo...');
            
            const media = await msg.downloadMedia();
            const filePath = path.join(__dirname, 'temp_files', `${msg.id.timestamp}_${msg.id.id}.tmp`);
            
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
    } else if (msg.hasMedia) {
        // Si tiene archivo pero no palabra clave
        await msg.reply('ℹ️ Recibí un archivo. Si deseas que lo analice, incluye palabras como "revisar", "analizar" o "scan" en tu mensaje.');
    }
});

// Resto del código (eventos qr, ready, etc.) permanece igual...
client.on('qr', qr => {
    qrcode.generate(qr, { small: true });
});

client.on('ready', () => {
    console.log('Client is ready!');
});

client.initialize();