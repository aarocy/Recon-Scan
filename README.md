# Recon-Scan

<img width="1349" height="355" alt="image" src="https://github.com/user-attachments/assets/57e9e643-54c8-41cd-9600-973de37c8bb7" />

<img width="1349" height="355" alt="image" src="https://github.com/user-attachments/assets/57e9e643-54c8-41cd-9600-973de37c8bb7" />

ReconScan is a open-source passive recon scanner with a FastAPI backend, async worker pipeline, and a single-page frontend.

The point is fast signal: run a scan, get module-by-module findings, and get an AI summary that can now be exported as a polished PDF report.

## What This Project Is (And Is Not)

- It is passive recon. It does not brute force endpoints, fuzz, or run active exploit logic.
- It is good for posture snapshots, triage, and reporting.
- It is not a substitute for full penetration testing.

## Features

- 13 passive modules:
  - Security headers
  - SSL/TLS
  - DNS + email auth (SPF/DMARC/MX)
  - WHOIS
  - Robots/sitemap
  - Subdomain enumeration
  - Tech fingerprinting
  - WAF detection
  - CORS checks
  - Cookie security checks
  - JS exposure checks
  - Directory exposure checks
  - Reputation checks
- Async execution with Redis + ARQ worker.
- Fallback to in-process background execution if queue enqueue fails.
- Optional AI summary via OpenRouter / Anthropic / OpenAI.
- PDF report generation from scan + AI summary.
- Frontend served directly by FastAPI (one URL, one app).

## One-Command Start (Local Dev)

If you just want it running quickly:

```bash
./start.sh
```

What this does:

- Creates `.env` from `.env.example` if missing.
- Creates `.venv` if needed.
- Installs dependencies from `requirements.txt`.
- Starts FastAPI with hot reload on `http://localhost:8000`.
- Forces `USE_ARQ_QUEUE=false` for easier no-Redis local startup.

Stop with `Ctrl+C`.

## One-Command Start (Docker)

```bash
./start-docker.sh
```

What this does:

- Creates `.env` from `.env.example` if missing.
- Starts API + worker + Redis with Docker Compose.

## Docker Start (Manual)

```bash
cp .env.example .env
docker compose up --build
```

## Local Development (Without Docker)

1. Install dependencies:

```bash
pip install -r requirements.txt
```

2. Create env file:

```bash
cp .env.example .env
```

3. Start API:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

4. Start worker in another terminal (recommended):

```bash
arq app.worker.WorkerSettings
```

5. Open:

`http://localhost:8000`

## PDF Reports

After a scan completes, click `Download PDF` in the UI.

Backend endpoint:

- `GET /scans/{scan_id}/report.pdf`

The report includes:

- Target and scan metadata
- AI executive summary (short + full narrative when available)
- Severity snapshot table
- Detailed module-by-module findings

## API

- `GET /health`
- `POST /scans`
  - body example:
    - `{ "target": "example.com" }`
    - `{ "target": "example.com", "byoapi_key": "...", "byoapi_provider": "your_provider" }`
  - notes:
    - `byoapi_key` rejected unless `ALLOW_BYO_API_KEY=true`
    - private / loopback / reserved targets are blocked
    - `user_id` is optional and kept for compatibility
- `GET /scans/{scan_id}`
- `GET /scans/{scan_id}/report.pdf`

## Configuration

From `.env.example`:

- `DATABASE_URL` (default: `sqlite:///./reconscan.db`)
- `REDIS_URL` (default: `redis://localhost:6379`)
- `USE_ARQ_QUEUE` (default: `true`)
- `RATE_LIMIT_PER_MINUTE` (default: `10`)
- `RATE_LIMIT_PER_DAY` (default: `200`)
- `ALLOWED_HOSTS` (default: `localhost,127.0.0.1`)
- `CORS_ALLOWED_ORIGINS` (default: local development origins)
- `ALLOW_BYO_API_KEY` (default: `false`)
- `OPENROUTER_API_KEY`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY` (optional)
- `VIRUSTOTAL_API_KEY`, `GOOGLE_SAFE_BROWSING_API_KEY` (optional)

## Notes

- If no external AI key is configured, ReconScan stores a local fallback summary.
- SQLite is the default storage engine for easy local use.
- This repo is intentionally lightweight and self-host friendly.

## License

MIT. See [LICENSE](./LICENSE).
