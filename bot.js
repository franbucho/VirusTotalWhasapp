require('dotenv').config();
const { Client, LocalAuth } = require('whatsapp-web.js');
const axios = require('axios');
const FormData = require('form-data');
const fs = require('fs');
const path = require('path');
const express = require('express');
const qrcode = require('qrcode'); // <--- CAMBIO: Librería añadida

// Configuración
const app = express();
const PORT = process.env.PORT || 3000; // Render inyecta la variable PORT
const VIRUSTOTAL_API_KEY = process.env.VT_API_KEY;
const MAX_FILE_SIZE_MB = 32;
const ACTIVATION_WORDS = ['revisar', 'scan', 'analizar', 'check', 'review', 'escanear'];
const RECONNECT_DELAY = 10000; // 10 segundos entre reconexiones

// Inicializar WhatsApp Client
const client = new Client({
    authStrategy: new LocalAuth({
        dataPath: path.join(__dirname, 'session_data') // Ruta donde se guardará/buscará la sesión
    }),
    puppeteer: {
        headless: true, // Importante: true para entornos de servidor (no se abre navegador visual)
        args: [
            '--no-sandbox',
            '--disable-setuid-sandbox',
            '--disable-dev-shm-usage', // Necesario para evitar errores en entornos sin GUI
            '--disable-gpu' // Opcional, pero recomendado en algunos entornos de servidor
        ]
    },
    takeoverOnConflict: true, // Forzar toma de control de sesión si ya está abierta en otro lugar
    restartOnAuthFail: true   // Reiniciar si falla la autenticación (ej. sesión corrupta)
});

// Servidor web para health checks de Render
app.get('/', (req, res) => {
    const status = client.info ? 'connected' : 'disconnected';
    res.status(200).json({
        status: status,
        service: 'WhatsApp VirusTotal Bot',
        uptime: process.uptime(), // Tiempo que lleva el proceso activo
        session: client.info || null // Información de la sesión del cliente (si está disponible)
    });
});

// El bot debe escuchar en el puerto proporcionado por Render
app.listen(PORT, () => {
    console.log(`Servidor health check escuchando en puerto ${PORT}`);
});

// Función para inicializar y manejar la reconexión del cliente de WhatsApp
function initializeClient() {
    client.initialize().catch(err => {
        console.error('⚠️ Error al iniciar cliente de WhatsApp:', err);
        console.log(`Reintentando iniciar cliente en ${RECONNECT_DELAY / 1000} segundos...`);
        setTimeout(initializeClient, RECONNECT_DELAY);
    });
}

// Función para escanear archivos con VirusTotal
async function scanFile(filePath) {
    try {
        if (!fs.existsSync(filePath)) {
            throw new Error('Archivo temporal no existe');
        }
        
        const fileStats = fs.statSync(filePath);
        const fileSizeMB = fileStats.size / (1024 * 1024);
        if (fileSizeMB > MAX_FILE_SIZE_MB) {
            throw new Error(`Archivo demasiado grande (${fileSizeMB.toFixed(2)}MB). Máximo permitido: ${MAX_FILE_SIZE_MB}MB`);
        }

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
        if (!analysisId) {
            throw new Error('No se obtuvo ID de análisis de VirusTotal');
        }

        console.log(`Archivo subido. ID de análisis: ${analysisId}`);
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
            throw new Error('Estructura de respuesta de VirusTotal inválida');
        }

        const { stats } = report.data.attributes;
        const totalEngines = Object.values(stats).reduce((sum, val) => sum + (val || 0), 0);
        const malicious = stats.malicious || 0;
        const sha256 = report.data.attributes.sha256 || '';

        return {
            malicious,
            totalEngines,
            stats,
            permalink: sha256 ? `https://www.virustotal.com/gui/file/${sha256}/detection` : 'Enlace no disponible'
        };
    } catch (error) {
        if (axios.isAxiosError(error)) {
            console.error('Error de Axios en scanFile:', error.response?.status, error.response?.data || error.message);
            throw new Error(`Fallo en el análisis de VirusTotal: ${error.response?.data?.error?.message || error.message}`);
        }
        console.error('Error general en scanFile:', error.message);
        throw new Error(`Fallo en el análisis: ${error.message}`);
    } finally {
        try {
            if (filePath && fs.existsSync(filePath)) {
                fs.unlinkSync(filePath);
                console.log(`Archivo temporal ${path.basename(filePath)} eliminado.`);
            }
        } catch (e) {
            console.error('Error eliminando archivo temporal:', e);
        }
    }
}

// --- SECCIÓN MODIFICADA ---
// Eventos del cliente de WhatsApp
client.on('qr', qr => {
    console.log('QR DATA GENERADO. Generando URL de imagen...');
    qrcode.toDataURL(qr, (err, url) => {
        if (err) {
            console.error('Error generando la URL del QR', err);
        } else {
            console.log('¡URL del QR generada! Cópiala y pégala en tu navegador para escanearla:');
            console.log(url);
        }
    });
});
// --- FIN DE LA SECCIÓN MODIFICADA ---

client.on('authenticated', () => {
    console.log('✅ Autenticación de WhatsApp exitosa.');
});

client.on('ready', () => {
    console.log('🚀 Bot de WhatsApp listo y conectado.');
    console.log('Sesión del cliente:', client.info);
});

client.on('disconnected', (reason) => {
    console.log(`⚠️ Sesión de WhatsApp desconectada: ${reason}`);
    try {
        client.destroy();
    } catch (e) {
        console.error('Error al destruir cliente desconectado:', e);
    }
    console.log(`Reconectando cliente en ${RECONNECT_DELAY / 1000} segundos...`);
    setTimeout(initializeClient, RECONNECT_DELAY);
});

client.on('message', async msg => {
    try {
        const hasActivationWord = ACTIVATION_WORDS.some(word => 
            msg.body.toLowerCase().includes(word.toLowerCase())
        );

        if (!msg.hasMedia || !hasActivationWord) {
            return;
        }

        await msg.reply('🔍 Analizando archivo... Por favor, espera.');
        
        const media = await msg.downloadMedia();
        if (!media || !media.data) {
            await msg.reply('❌ No se pudo descargar el archivo adjunto.');
            return;
        }

        const tempDir = path.join(__dirname, 'temp');
        if (!fs.existsSync(tempDir)) {
            fs.mkdirSync(tempDir, { recursive: true });
        }
        
        const filePath = path.join(tempDir, `${Date.now()}_${msg.id.id}.${media.mimetype.split('/')[1] || 'tmp'}`);
        fs.writeFileSync(filePath, Buffer.from(media.data, 'base64'));
        console.log(`Archivo temporal guardado: ${filePath}`);

        const result = await scanFile(filePath);

        const response = [
            '📊 *Resultados del análisis de VirusTotal*',
            `• Motores detectados como maliciosos: *${result.malicious}*`,
            `• Motores totales analizados: ${result.totalEngines}`,
            `• Enlace completo del reporte: ${result.permalink}`,
            '_Powered by VirusTotal_'
        ].join('\n');

        await msg.reply(response);

    } catch (error) {
        console.error('❌ Error procesando mensaje de WhatsApp:', error);
        await msg.reply(`❌ Error en el análisis: ${error.message || 'Error desconocido'}`);
    }
});

// Iniciar el cliente de WhatsApp al iniciar la aplicación
initializeClient();

// Manejo de errores globales para evitar que el proceso se caiga
process.on('unhandledRejection', (reason, promise) => {
    console.error('🚨 Unhandled Rejection at:', promise, 'reason:', reason);
});

process.on('uncaughtException', (err) => {
    console.error('🔥 Uncaught Exception:', err);
    console.log('Reiniciando cliente de WhatsApp debido a una excepción no capturada...');
    setTimeout(initializeClient, RECONNECT_DELAY);
});