require('dotenv').config();
const { Client, LocalAuth } = require('whatsapp-web.js');
const qrcode = require('qrcode-terminal'); // Todavía lo necesitamos para generar el QR data
const axios = require('axios');
const FormData = require('form-data');
const fs = require('fs');
const path = require('path');
const express = require('express');

// Configuración
const app = express();
const PORT = process.env.PORT || 3000;
const VIRUSTOTAL_API_KEY = process.env.VT_API_KEY;
const MAX_FILE_SIZE_MB = 32;
const ACTIVATION_WORDS = ['revisar', 'scan', 'analizar', 'check', 'review', 'escanear'];
const RECONNECT_DELAY = 10000; // 10 segundos entre reconexiones

// --- CAMBIO AQUÍ: Definimos el número de administrador para recibir el QR ---
const ADMIN_WA_NUMBER = '12128378524@c.us'; // Tu número de WhatsApp, con código de país y @c.us
// Puedes dejarlo como variable de entorno si prefieres: process.env.ADMIN_WA_NUMBER;
// En ese caso, asegúrate de configurarlo en Render.
// -----------------------------------------------------------------------

// Inicializar WhatsApp Client
const client = new Client({
    authStrategy: new LocalAuth({
        dataPath: path.join(__dirname, 'session_data')
    }),
    puppeteer: {
        headless: true,
        args: [
            '--no-sandbox',
            '--disable-setuid-sandbox',
            '--disable-dev-shm-usage'
        ]
    },
    takeoverOnConflict: true, // Forzar toma de control de sesión
    restartOnAuthFail: true   // Reiniciar si falla la autenticación
});

// Servidor web para health checks
app.get('/', (req, res) => {
    const status = client.info ? 'connected' : 'disconnected';
    res.status(200).json({
        status: status,
        service: 'WhatsApp VirusTotal Bot',
        uptime: process.uptime(),
        session: client.info || null
    });
});

app.listen(PORT, () => {
    console.log(`Servidor health check en puerto ${PORT}`);
});

// Función para reconexión automática
function initializeClient() {
    client.initialize().catch(err => {
        console.error('Error al iniciar cliente:', err);
        setTimeout(initializeClient, RECONNECT_DELAY);
    });
}

// --- CAMBIO AQUÍ: Función para enviar el enlace QR ---
async function sendQrLinkToAdmin(qrData) {
    if (!ADMIN_WA_NUMBER) {
        console.warn("ADMIN_WA_NUMBER no está configurado. No se enviará el enlace del QR.");
        return;
    }

    // Generar la URL del QR de Google Charts
    const qrImageUrl = `https://chart.googleapis.com/chart?cht=qr&chs=300x300&chl=${encodeURIComponent(qrData)}`;

    try {
        // Enviar el enlace del QR directamente al número del administrador
        await client.sendMessage(ADMIN_WA_NUMBER, `Por favor, escanea este QR para autenticar el bot:\n${qrImageUrl}\n\n(Este enlace es válido por un tiempo limitado. Si expira, el bot se reiniciará para generar uno nuevo)`);
        console.log(`Enviado enlace QR a ${ADMIN_WA_NUMBER}`);
    } catch (error) {
        console.error(`Error al enviar el enlace QR a ${ADMIN_WA_NUMBER}:`, error);
        // Si falla enviar el mensaje, al menos imprímelo en el log para verlo manualmente
        console.log(`Fallback: QR Image URL for manual scan: ${qrImageUrl}`);
    }
}
// ---------------------------------------------------

// Función para escanear archivos con VirusTotal
async function scanFile(filePath) {
    try {
        if (!fs.existsSync(filePath)) throw new Error('Archivo temporal no existe');
        
        const fileStats = fs.statSync(filePath); 
        const fileSizeMB = fileStats.size / (1024 * 1024); 
        if (fileSizeMB > MAX_FILE_SIZE_MB) throw new Error(`Archivo demasiado grande (${fileSizeMB.toFixed(2)}MB)`);

        const formData = new FormData();
        formData.append('file', fs.createReadStream(filePath));

        const uploadResponse = await axios.post(
            'https://www.virustotal.com/api/v3/files',
            formData,
            {
                headers: {
                    'x-apikey': VIRUSTOTAL_API_KEY,
                    ...formData.getHeaders()
                },
                timeout: 60000
            }
        );

        const analysisId = uploadResponse.data?.data?.id;
        if (!analysisId) throw new Error('No se obtuvo ID de análisis');

        console.log(`Archivo subido. ID: ${analysisId}`);
        await new Promise(resolve => setTimeout(resolve, 30000));

        const reportResponse = await axios.get(
            `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
            {
                headers: { 'x-apikey': VIRUSTOTAL_API_KEY },
                timeout: 30000
            }
        );

        const report = reportResponse.data;
        if (!report?.data?.attributes?.stats) {
            throw new Error('Estructura de respuesta inválida');
        }

        const { stats } = report.data.attributes; 
        const totalEngines = Object.values(stats).reduce((sum, val) => sum + (val || 0), 0);
        const malicious = stats.malicious || 0;
        const sha256 = report.data.attributes.sha256 || '';

        return {
            malicious,
            totalEngines,
            stats, 
            permalink: sha256 ? `https://www.virustotal.com/gui/file/${sha256}/detection` : 'No disponible'
        };
    } catch (error) {
        console.error('Error en scanFile:', error.message);
        throw new Error(`Fallo en el análisis: ${error.message}`);
    } finally {
        try {
            if (filePath && fs.existsSync(filePath)) fs.unlinkSync(filePath);
        } catch (e) {
            console.error('Error eliminando archivo temporal:', e);
        }
    }
}

// Eventos de WhatsApp
client.on('qr', async qr => { // Marcado como async para usar await
    // Ya no usamos qrcode.generate(qr, { small: true });
    console.log('QR data generado. Intentando enviar como enlace...');
    await sendQrLinkToAdmin(qr); // Llamamos a la nueva función
});

client.on('authenticated', () => {
    console.log('Autenticación exitosa ✅');
});

client.on('ready', () => {
    console.log('Bot listo 🚀 | Sesión:', client.info);
});

client.on('disconnected', (reason) => {
    console.log(`⚠️ Sesión desconectada: ${reason}`);
    console.log(`Reconectando en ${RECONNECT_DELAY/1000} segundos...`);
    
    try {
        client.destroy();
    } catch (e) {
        console.error('Error al destruir cliente:', e);
    }
    
    setTimeout(initializeClient, RECONNECT_DELAY);
});

client.on('message', async msg => {
    try {
        const hasActivationWord = ACTIVATION_WORDS.some(word => 
            msg.body.toLowerCase().includes(word.toLowerCase())
        );

        if (!msg.hasMedia || !hasActivationWord) return;

        await msg.reply('🔍 Analizando archivo...');
        const media = await msg.downloadMedia();
        const filePath = path.join(__dirname, 'temp', `${Date.now()}_${msg.id.id}.tmp`);

        if (!fs.existsSync(path.dirname(filePath))) {
            fs.mkdirSync(path.dirname(filePath), { recursive: true });
        }
        fs.writeFileSync(filePath, Buffer.from(media.data, 'base64'));

        const result = await scanFile(filePath);
        const response = [
            '📊 *Resultados del análisis*',
            `• Motores totales: ${result.totalEngines}`,
            `• Detectado como malicioso: ${result.malicious}`,
            `• Enlace completo: ${result.permalink}`,
            '_Powered by VirusTotal_'
        ].join('\n');

        await msg.reply(response);
    } catch (error) {
        console.error('Error procesando mensaje:', error);
        await msg.reply(`❌ Error: ${error.message}`);
    }
});

// Iniciar cliente
initializeClient();

// Manejo de errores globales
process.on('unhandledRejection', (err) => {
    console.error('Unhandled Rejection:', err);
});

process.on('uncaughtException', (err) => {
    console.error('Uncaught Exception:', err);
    setTimeout(initializeClient, RECONNECT_DELAY);
});