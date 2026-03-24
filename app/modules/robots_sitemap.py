import httpx

SENSITIVE_PATHS = [
    "/admin", "/wp-admin", "/phpmyadmin", "/api",
    "/backup", "/config", "/.env", "/secret",
    "/private", "/internal", "/dashboard"
]

async def run(target: str) -> dict:
    result = {
        "module": "robots_sitemap",
        "findings": {},
        "severity": "info"
    }

    findings = {
        "robots_txt": None,
        "sitemap": None,
        "sensitive_paths": [],
        "disallowed_paths": []
    }

    base_url = f"https://{target}"

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            robots = await client.get(f"{base_url}/robots.txt", follow_redirects=True)
            if robots.status_code == 200:
                findings["robots_txt"] = "present"
                lines = robots.text.splitlines()
                disallowed = [
                    l.split(":", 1)[1].strip()
                    for l in lines
                    if l.lower().startswith("disallow:")
                ]
                findings["disallowed_paths"] = disallowed

                sensitive = [
                    p for p in disallowed
                    if any(s in p.lower() for s in SENSITIVE_PATHS)
                ]
                findings["sensitive_paths"] = sensitive

                if sensitive:
                    result["severity"] = "medium"
            else:
                findings["robots_txt"] = "missing"

            sitemap = await client.get(f"{base_url}/sitemap.xml", follow_redirects=True)
            findings["sitemap"] = "present" if sitemap.status_code == 200 else "missing"

    except Exception as e:
        findings["error"] = str(e)

    result["findings"] = findings
    return result
