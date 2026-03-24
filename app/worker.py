from app.modules import security_headers, ssl_tls, dns_email, whois, robots_sitemap, reputation, subdomains, tech_fingerprint, waf_detection, cors_check, cookie_security, js_exposure, directory_exposure
from app.database import storage
from app.providers import get_provider
from arq.connections import RedisSettings as ArqRedisSettings
import asyncio
import traceback
import os
import json
from collections import Counter

MODULE_MAP = {
    "security_headers": security_headers.run,
    "ssl_tls": ssl_tls.run,
    "dns_email": dns_email.run,
    "whois": whois.run,
    "robots_sitemap": robots_sitemap.run,
    "reputation": reputation.run,
    "subdomains": subdomains.run,
    "tech_fingerprint": tech_fingerprint.run,
    "waf_detection": waf_detection.run,
    "cors_check": cors_check.run,
    "cookie_security": cookie_security.run,
    "js_exposure": js_exposure.run,
    "directory_exposure": directory_exposure.run,
}

def _fallback_summary(target: str, modules: list, results: list) -> dict:
    severity_counter = Counter((r.get("severity") or "info") for r in results)
    critical = severity_counter.get("critical", 0)
    high = severity_counter.get("high", 0)
    medium = severity_counter.get("medium", 0)
    low = severity_counter.get("low", 0)

    short = (
        f"Scan for {target} finished. "
        f"Critical: {critical}, High: {high}, Medium: {medium}, Low: {low} findings across {len(modules)} modules."
    )

    notable = []
    for module, result in zip(modules, results):
        severity = result.get("severity", "info")
        if severity in {"critical", "high"}:
            notable.append(f"- {module}: {severity}")
    if not notable:
        notable.append("- No critical/high findings were detected.")

    full = "\n".join(
        [
            "Summary generated without external AI provider.",
            "Severity distribution:",
            f"- critical: {critical}",
            f"- high: {high}",
            f"- medium: {medium}",
            f"- low: {low}",
            "",
            "Notable modules:",
            *notable[:8],
        ]
    )
    return {"short": short, "full": full}


async def run_scan(ctx, scan_id: str, target: str, modules: list, byoapi_key: str = None, byoapi_provider: str = None):
    async def run_module(module: str):
        storage.update_scan_result(
            scan_id=scan_id,
            module=module,
            status="running",
        )

        if module in MODULE_MAP:
            result = await MODULE_MAP[module](target)
        else:
            result = {
                "findings": {"status": "module coming soon"},
                "severity": "info"
            }

        storage.update_scan_result(
            scan_id=scan_id,
            module=module,
            status="complete",
            raw_data=json.dumps(result["findings"]),
            severity=result["severity"],
        )

        return result

    results = await asyncio.gather(*[run_module(m) for m in modules])

    summary_saved = False
    if byoapi_key:
        try:
            provider_name = byoapi_provider or "openrouter"
            print(f"Running AI summary with {provider_name}")
            provider = get_provider(provider_name, byoapi_key)
            scan_context = {
                "target": target,
                "modules": dict(zip(modules, [r["findings"] for r in results]))
            }
            summary = await provider.summarize(scan_context)
            print(f"AI summary complete: {summary.short_narrative[:80]}")

            storage.upsert_summary(
                scan_id=scan_id,
                short_narrative=summary.short_narrative,
                full_narrative=summary.full_narrative,
                model_used=summary.model_used,
                provider=summary.provider,
            )
            summary_saved = True
        except Exception as e:
            print(f"AI summary failed: {e}")
            traceback.print_exc()

    if not summary_saved:
        fallback = _fallback_summary(target, modules, results)
        storage.upsert_summary(
            scan_id=scan_id,
            short_narrative=fallback["short"],
            full_narrative=fallback["full"],
            model_used="fallback-v1",
            provider="local",
        )

    storage.update_scan(scan_id=scan_id, status="complete")


class WorkerSettings:
    functions = [run_scan]
    redis_settings = ArqRedisSettings.from_dsn(
        os.environ.get("REDIS_URL", "redis://localhost:6379")
    )
