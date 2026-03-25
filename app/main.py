import asyncio
import logging
import os
import uuid
from typing import Optional

from arq import create_pool
from arq.connections import RedisSettings as ArqRedisSettings
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from starlette.middleware.base import BaseHTTPMiddleware

from app.config import settings
from app.database import storage
from app.pdf_report import build_scan_pdf
from app.rate_limit import InMemoryRateLimiter
from app.security import normalize_and_validate_target

logger = logging.getLogger(__name__)

app = FastAPI(title="ReconScan API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_allowed_origins_list,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts_list or ["localhost", "127.0.0.1"])

ALL_MODULES = [
    "security_headers",
    "ssl_tls",
    "dns_email",
    "whois",
    "robots_sitemap",
    "subdomains",
    "tech_fingerprint",
    "waf_detection",
    "cors_check",
    "cookie_security",
    "js_exposure",
    "directory_exposure",
    "reputation",
]

rate_limiter = InMemoryRateLimiter(
    per_minute=settings.rate_limit_per_minute,
    per_day=settings.rate_limit_per_day,
)

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["Cache-Control"] = "no-store"
        return response

app.add_middleware(SecurityHeadersMiddleware)


class ScanRequest(BaseModel):
    target: str
    user_id: Optional[str] = None
    byoapi_key: Optional[str] = None
    byoapi_provider: Optional[str] = None


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/scans")
async def create_scan(request: ScanRequest, req: Request):
    ip = req.client.host if req.client else "unknown"
    decision = rate_limiter.check(ip)
    if not decision.allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded: {decision.reason}. Retry in {decision.retry_after_seconds}s.",
            headers={"Retry-After": str(decision.retry_after_seconds)},
        )

    try:
        normalized_target = normalize_and_validate_target(request.target)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if request.byoapi_key and not settings.allow_byo_api_key:
        raise HTTPException(status_code=403, detail="BYO API keys are disabled on this deployment")

    scan_id = str(uuid.uuid4())
    api_key = request.byoapi_key or settings.openrouter_api_key
    provider = request.byoapi_provider or "openrouter"

    storage.create_scan(
        scan_id=scan_id,
        user_id=request.user_id,
        target_domain=normalized_target,
    )

    for module in ALL_MODULES:
        storage.create_scan_result(
            result_id=str(uuid.uuid4()),
            scan_id=scan_id,
            module=module,
        )

    if settings.use_arq_queue:
        try:
            redis_url = os.environ.get("REDIS_URL", settings.redis_url)
            redis = await create_pool(ArqRedisSettings.from_dsn(redis_url))
            await redis.enqueue_job(
                "run_scan",
                scan_id,
                normalized_target,
                ALL_MODULES,
                api_key,
                provider,
            )
        except Exception:
            logger.exception("ARQ enqueue failed; using in-process background task.")
            from app.worker import run_scan

            asyncio.create_task(
                run_scan({}, scan_id, normalized_target, ALL_MODULES, api_key, provider)
            )
    else:
        from app.worker import run_scan

        asyncio.create_task(
            run_scan({}, scan_id, normalized_target, ALL_MODULES, api_key, provider)
        )

    return {
        "scan_id": scan_id,
        "status": "queued",
        "modules": ALL_MODULES,
    }


@app.get("/scans/{scan_id}")
async def get_scan(scan_id: str):
    scan = storage.get_scan(scan_id)
    results = storage.get_results(scan_id)
    summary = storage.get_summary(scan_id)

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return {
        "scan": scan,
        "results": results,
        "ai_summary": summary,
    }


@app.get("/scans/{scan_id}/report.pdf")
async def download_scan_report(scan_id: str):
    scan = storage.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    results = storage.get_results(scan_id)
    summary = storage.get_summary(scan_id)
    pdf_data = build_scan_pdf(scan=scan, results=results, summary=summary)

    filename_target = (scan.get("target_domain") or "target").replace("/", "_")
    headers = {
        "Content-Disposition": f'attachment; filename="reconscan-{filename_target}-{scan_id[:8]}.pdf"'
    }
    return Response(content=pdf_data, media_type="application/pdf", headers=headers)


app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")
