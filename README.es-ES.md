

# Recon-Scan

<img width="1349" height="355" alt="image" src="https://github.com/user-attachments/assets/57e9e643-54c8-41cd-9600-973de37c8bb7" />

ReconScan es un escáner de reconocimiento pasivo de código abierto con un backend de FastAPI, un pipeline de trabajadores asíncronos y un frontend de una sola página. Puedes consultar el sitio desplegado en [https://recon-scan.vercel.app/](https://recon-scan.vercel.app/) 

La idea es obtener resultados rápidos: ejecuta un análisis, obtén hallazgos módulo por módulo y genera un resumen con IA que ahora se puede exportar como un informe PDF profesional.

## Qué es este proyecto (y qué no es)

- Se trata de reconocimiento pasivo. No realiza fuerza bruta en puntos finales, fuzzing ni ejecuta lógica de explotación activa.
- Es útil para instantáneas de postura de seguridad, triaje e informes.
- No es un sustituto de una prueba de penetración completa.

## Características

- 13 módulos pasivos:
  - Encabezados de seguridad
  - SSL/TLS
  - DNS y autenticación de correo (SPF/DMARC/MX)
  - WHOIS
  - Robots/sitemap
  - Enumeración de subdominios
  - Huella tecnológica (fingerprinting)
  - Detección de WAF
  - Verificaciones CORS
  - Verificaciones de seguridad de cookies
  - Verificaciones de exposición de JS
  - Verificaciones de exposición de directorios
  - Verificaciones de reputación
- Ejecución asíncrona con Redis y trabajador ARQ.
- Ejecución de respaldo en segundo plano dentro del mismo proceso si el encolamiento falla.
- Resumen opcional con IA a través de OpenRouter / Anthropic / OpenAI.
- Generación de informes PDF a partir del análisis y el resumen de IA.
- Frontend servido directamente por FastAPI (una URL, una aplicación).

## Inicio con un solo comando (Desarrollo local)

Si solo deseas que se ejecute rápidamente:

```bash
./start.sh
```

Lo que hace:

- Crea `.env` a partir de `.env.example` si falta.
- Crea `.venv` si es necesario.
- Instala las dependencias desde `requirements.txt`.
- Inicia FastAPI con recarga automática en `http://localhost:8000`.
- Fuerza `USE_ARQ_QUEUE=false` para un inicio local sin Redis más sencillo.

Detén con `Ctrl+C`.

## Inicio con un solo comando (Docker)

```bash
./start-docker.sh
```

Lo que hace:

- Crea `.env` a partir de `.env.example` si falta.
- Inicia API + trabajador + Redis con Docker Compose.

## Inicio de Docker (Manual)

```bash
cp .env.example .env
docker compose up --build
```

## Desarrollo local (Sin Docker)

1. Instala las dependencias:

```bash
pip install -r requirements.txt
```

2. Crea el archivo de entorno:

```bash
cp .env.example .env
```

3. Inicia la API:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

4. Inicia el trabajador en otra terminal (recomendado):

```bash
arq app.worker.WorkerSettings
```

5. Abre:

`http://localhost:8000`

## Ejecutar pruebas

Instala las dependencias de prueba:

```bash
pip install -r requirements-dev.txt
```

Ejecuta la suite completa:

```bash
pytest -q
```

## Informes PDF

Después de que se complete un análisis, haz clic en `Download PDF` en la interfaz.

Endpoint del backend:

- `GET /scans/{scan_id}/report.pdf`

El informe incluye:

- Metadatos del objetivo y del análisis
- Resumen ejecutivo de IA (breve + narrativa completa cuando esté disponible)
- Tabla instantánea de severidad
- Hallazgos detallados módulo por módulo

## API

- `GET /health`
- `POST /scans`
  - ejemplo del cuerpo:
    - `{ "target": "example.com" }`
    - `{ "target": "example.com", "byoapi_key": "...", "byoapi_provider": "your_provider" }`
  - notas:
    - `byoapi_key` se rechaza a menos que `ALLOW_BYO_API_KEY=true`
    - los objetivos privados / de bucle local (loopback) / reservados están bloqueados
    - `user_id` es opcional y se conserva por compatibilidad
- `GET /scans/{scan_id}`
- `GET /scans/{scan_id}/report.pdf`

## Configuración

Desde `.env.example`:

- `DATABASE_URL` (predeterminado: `sqlite:///./reconscan.db`)
- `REDIS_URL` (predeterminado: `redis://localhost:6379`)
- `USE_ARQ_QUEUE` (predeterminado: `true`)
- `RATE_LIMIT_PER_MINUTE` (predeterminado: `10`)
- `RATE_LIMIT_PER_DAY` (predeterminado: `200`)
- `ALLOWED_HOSTS` (predeterminado: `localhost,127.0.0.1`)
- `CORS_ALLOWED_ORIGINS` (predeterminado: orígenes de desarrollo local)
- `ALLOW_BYO_API_KEY` (predeterminado: `false`)
- `OPENROUTER_API_KEY`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY` (opcional)
- `VIRUSTOTAL_API_KEY`, `GOOGLE_SAFE_BROWSING_API_KEY` (opcional)

## Contribuir

Se agradecen las contribuciones, especialmente en torno a módulos de reconocimiento pasivo, generación de informes, UX del frontend y cobertura de pruebas.

Lee las pautas completas de contribución antes de abrir un pull request:

[Contributing Guide](./CONTRIBUTING.md)

## Notas

- Si no se configura una clave de IA externa, ReconScan almacena un resumen de respaldo local.
- SQLite es el motor de almacenamiento predeterminado para facilitar el uso local.
- Este repositorio es intencionalmente ligero y amigable para autoalojamiento (self-host).

## Licencia

MIT. Consulta [LICENSE](./LICENSE).
