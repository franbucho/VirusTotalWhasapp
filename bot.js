require('dotenv').config();
const { Client, LocalAuth } = require('whatsapp-web.js');
const qrcode = require('qrcode-terminal');
const axios = require('axios');
const FormData = require('form-data');
const fs = require('fs');
const path = require('path');
const express = require('express');

// Configuración
const app = express();
const PORT = process.env.PORT || 3000;
const VIRUSTOTAL_API_KEY = process.env.VT_API_KEY || 'tu-api-key'; // Usa variables de entorno
const MAX_FILE_SIZE_MB = 32;
const ACTIVATION_WORDS = ['revisar', 'scan', 'analizar', 'check', 'review', 'escanear'];

// Inicializar WhatsApp Client
const client = new Client({
    authStrategy: new LocalAuth({
        dataPath: path.join(__dirname, 'session_data') // Guarda sesiones persistentes
    }),
    puppeteer: {
        headless: true,
        args: [
            '--no-sandbox',
            '--disable-setuid-sandbox',
            '--disable-dev-shm-usage'
        ]
    }
});

// Servidor web para health checks
app.get('/', (req, res) => {
    res.status(200).json({
        status: 'online',
        service: 'WhatsApp VirusTotal Bot',
        uptime: process.uptime()
    });
});

app.listen(PORT, () => {
    console.log(`Servidor health check en puerto ${PORT}`);
});

// Función para escanear archivos con VirusTotal
async function scanFile(filePath) {
    try {
        // Validación del archivo
        if (!fs.existsSync(filePath)) throw new Error('Archivo temporal no existe');
        
        const stats = fs.statSync(filePath);
        const fileSizeMB = stats.size / (1024 * 1024);
        if (fileSizeMB > MAX_FILE_SIZE_MB) throw new Error(`Archivo demasiado grande (${fileSizeMB.toFixed(2)}MB)`);

        // Subir a VirusTotal
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
        await new Promise(resolve => setTimeout(resolve, 30000)); // Espera 30 segundos

        // Obtener resultados
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
client.on('qr', qr => {
    qrcode.generate(qr, { small: true });
});

client.on('authenticated', () => {
    console.log('Autenticación exitosa ✅');
});

client.on('ready', () => {
    console.log('Bot listo 🚀');
});

client.on('disconnected', (reason) => {
    console.log('Desconectado:', reason);
    console.log('Reiniciando...');
    client.initialize();
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

        // Asegurar directorio temporal
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

// Iniciar
client.initialize();

// Manejo de errores globales
process.on('unhandledRejection', (err) => {
    console.error('Unhandled Rejection:', err);
});

process.on('uncaughtException', (err) => {
    console.error('Uncaught Exception:', err);
});