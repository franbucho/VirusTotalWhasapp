const { Client, LocalAuth } = require('whatsapp-web.js');
const qrcode = require('qrcode-terminal');
const axios = require('axios');
const FormData = require('form-data');
const fs = require('fs');
const path = require('path');

// Configuración
const VIRUSTOTAL_API_KEY = '2063838b3b3f8b6fe796203c289b68621b849db1bfdb525b5389249e4c9db469';
const MAX_FILE_SIZE_MB = 32; // VirusTotal tiene límite de 32MB para la API gratuita

// Inicializar cliente de WhatsApp
const client = new Client({
    authStrategy: new LocalAuth(),
    puppeteer: { 
        headless: true,
        args: ['--no-sandbox', '--disable-setuid-sandbox']
    }
});

// Función mejorada para escanear archivos
async function scanFile(filePath) {
    try {
        // Verificar tamaño del archivo
        const fileStats = fs.statSync(filePath);
        const fileSizeInMB = fileStats.size / (1024 * 1024);
        
        if (fileSizeInMB > MAX_FILE_SIZE_MB) {
            throw new Error(`El archivo es demasiado grande (${fileSizeInMB.toFixed(2)}MB). El límite es ${MAX_FILE_SIZE_MB}MB.`);
        }

        // Paso 1: Subir el archivo
        const formData = new FormData();
        formData.append('file', fs.createReadStream(filePath));

        console.log('Subiendo archivo a VirusTotal...');
        const uploadResponse = await axios.post(
            'https://www.virustotal.com/api/v3/files',
            formData,
            {
                headers: {
                    'x-apikey': VIRUSTOTAL_API_KEY,
                    ...formData.getHeaders()
                },
                maxContentLength: Infinity,
                maxBodyLength: Infinity
            }
        );

        const analysisId = uploadResponse.data.data.id;
        console.log('ID de análisis:', analysisId);

        // Paso 2: Esperar y obtener resultados
        await new Promise(resolve => setTimeout(resolve, 20000)); // Esperar 20 segundos

        console.log('Obteniendo reporte...');
        const reportResponse = await axios.get(
            `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
            {
                headers: {
                    'x-apikey': VIRUSTOTAL_API_KEY
                }
            }
        );

        const report = reportResponse.data;
        console.log('Respuesta de VirusTotal:', JSON.stringify(report, null, 2));

        // Verificar si la respuesta tiene la estructura esperada
        if (!report.data || !report.data.attributes || !report.data.attributes.stats) {
            throw new Error('La respuesta de VirusTotal no tiene la estructura esperada');
        }

        const stats = report.data.attributes.stats;
        const totalEngines = (stats.harmless || 0) + (stats.malicious || 0) + 
                           (stats.suspicious || 0) + (stats.undetected || 0);
        const malicious = stats.malicious || 0;
        const sha256 = report.data.attributes.sha256;
        const permalink = sha256 ? `https://www.virustotal.com/gui/file/${sha256}/detection` : 'No disponible';

        return {
            malicious,
            totalEngines,
            stats,
            permalink
        };
    } catch (error) {
        console.error('Error al escanear con VirusTotal:', error.response?.data || error.message);
        throw error;
    }
}

// Eventos de WhatsApp
client.on('qr', qr => {
    qrcode.generate(qr, { small: true });
});

client.on('ready', () => {
    console.log('Client is ready!');
});

client.on('message', async msg => {
    if (msg.hasMedia) {
        try {
            await msg.reply('🔍 Recibí un archivo, escaneando con VirusTotal...');
            
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
    }
});

// Manejo de errores globales
process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

process.on('uncaughtException', (error) => {
    console.error('Uncaught Exception:', error);
});

// Iniciar el cliente
client.initialize();