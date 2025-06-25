# 📱 WhatsApp VirusTotal Bot

Un bot de WhatsApp que analiza archivos adjuntos utilizando la API de VirusTotal para detectar posibles amenazas de malware.

## 🚀 Características

- Escanea archivos recibidos por WhatsApp con VirusTotal
- Proporciona un reporte detallado de análisis
- Soporta múltiples formatos de archivo (hasta 32MB)
- Fácil de configurar y usar

## 📋 Requisitos

- Node.js v16 o superior
- Cuenta de WhatsApp (para el bot)
- API Key de VirusTotal (gratuita o premium)

## ⚙️ Instalación

1. Clona el repositorio o descarga el código
```bash
git clone https://github.com/tu-usuario/whatsapp-virustotal-bot.git
cd whatsapp-virustotal-bot
```

2. Instala las dependencias
```bash
npm install
```

3. Configura tu API Key de VirusTotal
   - Edita el archivo `bot.js` y reemplaza:
   ```javascript
   const VIRUSTOTAL_API_KEY = 'tu-api-key-aqui';
   ```

## 🏃‍♂️ Uso

1. Inicia el bot
```bash
node bot.js
```

2. Escanea el código QR que aparecerá en la terminal con WhatsApp:
   - Abre WhatsApp en tu teléfono
   - Ve a Ajustes → Dispositivos vinculados → Vincular un dispositivo

3. Envía cualquier archivo al número del bot y recibirás un análisis de VirusTotal

## 🛠️ Configuración avanzada

Puedes modificar estas variables en el código:

```javascript
const MAX_FILE_SIZE_MB = 32; // Cambia el límite de tamaño de archivo
const ANALYSIS_WAIT_TIME = 20000; // Tiempo de espera para el análisis (ms)
```

## 📜 Licencia

Este proyecto está bajo la licencia MIT. Ver [LICENSE](LICENSE) para más detalles.

## ⚠️ Limitaciones

- La API gratuita de VirusTotal tiene un límite de 4 solicitudes por minuto
- Archivos mayores a 32MB no serán procesados
- Requiere conexión a internet estable

## 🤝 Contribuciones

Las contribuciones son bienvenidas. Por favor abre un issue o pull request.

---

Hecho con ❤️ por [Tu Nombre] | Usa responsablemente
