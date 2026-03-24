# Recon-Scan

<img width="1349" height="355" alt="image" src="https://github.com/user-attachments/assets/57e9e643-54c8-41cd-9600-973de37c8bb7" />

ReconScan is an open-source passive recon API + frontend for security testing and learning.

The project now runs without Supabase, UUID-based user identity, or Stripe dependencies. It uses local SQLite by default so anyone can test it for free.

## Features

- Passive recon modules (headers, TLS, DNS, WHOIS, subdomains, WAF, CORS, cookies, JS exposure, directory checks, reputation)
- Async scan execution with ARQ + Redis
- Automatic fallback to in-process background task if Redis/ARQ is unavailable
- In-memory per-IP rate limiting with per-minute and per-day limits
- Optional AI summary generation (OpenRouter, Anthropic, OpenAI)

## Quick start

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

4. (Optional) Start worker queue if you want Redis + ARQ:

```bash
arq app.worker.WorkerSettings
```

If ARQ enqueue fails, API automatically falls back to in-process execution.

5. Open frontend:

- Serve `frontend/index.html` via any static server.
- By default:
  - `file://` or `localhost` frontend uses `http://localhost:8000`
  - hosted frontend uses same-origin API (`window.location.origin`)
- You can override API base with:
  - `window.RECONSCAN_API` before script execution, or
  - `localStorage.setItem("reconscan_api", "https://your-api-host")`

## Configuration

See `.env.example`:

- `DATABASE_URL` default `sqlite:///./reconscan.db`
- `REDIS_URL` default `redis://localhost:6379`
- `USE_ARQ_QUEUE` default `true`
- `RATE_LIMIT_PER_MINUTE` default `10`
- `RATE_LIMIT_PER_DAY` default `200`
- `ALLOWED_HOSTS` default `localhost,127.0.0.1`
- `CORS_ALLOWED_ORIGINS` default local dev origins only
- `ALLOW_BYO_API_KEY` default `false`
- `OPENROUTER_API_KEY` / `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` optional
- `VIRUSTOTAL_API_KEY` / `GOOGLE_SAFE_BROWSING_API_KEY` optional

## API

- `GET /health`
- `POST /scans`
  - body: `{ "target": "example.com", "byoapi_key": "...", "byoapi_provider": "openrouter" }`
  - `byoapi_key` is rejected unless `ALLOW_BYO_API_KEY=true`
  - private, loopback, and reserved targets are blocked
  - `user_id` is optional for backward compatibility but not required
- `GET /scans/{scan_id}`

## License

MIT. See [LICENSE](./LICENSE).
