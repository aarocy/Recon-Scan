import httpx

SENSITIVE_PATHS = [
    "/.env",
    "/.git/config",
    "/config.php",
    "/wp-config.php",
    "/admin",
    "/administrator",
    "/phpmyadmin",
    "/backup",
    "/backup.zip",
    "/db.sql",
    "/.htaccess",
    "/server-status",
    "/api/v1",
    "/api/v2",
    "/swagger",
    "/swagger-ui.html",
    "/api-docs",
    "/actuator",
    "/actuator/health",
    "/.DS_Store",
    "/crossdomain.xml",
    "/security.txt",
    "/.well-known/security.txt",
]

async def run(target: str) -> dict:
    result = {
        "module": "directory_exposure",
        "findings": {},
        "severity": "info"
    }

    findings = {
        "exposed_paths": [],
        "interesting_paths": [],
        "total_checked": len(SENSITIVE_PATHS)
    }

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            for path in SENSITIVE_PATHS:
                try:
                    response = await client.get(
                        f"https://{target}{path}",
                        follow_redirects=False
                    )
                    if response.status_code == 200:
                        findings["exposed_paths"].append({
                            "path": path,
                            "status": response.status_code,
                            "size": len(response.content)
                        })
                    elif response.status_code in [301, 302, 403]:
                        findings["interesting_paths"].append({
                            "path": path,
                            "status": response.status_code
                        })
                except Exception:
                    continue

            if len(findings["exposed_paths"]) >= 3:
                result["severity"] = "critical"
            elif len(findings["exposed_paths"]) >= 1:
                result["severity"] = "high"
            elif len(findings["interesting_paths"]) >= 3:
                result["severity"] = "medium"

    except Exception as e:
        findings["error"] = str(e)

    result["findings"] = findings
    return result

