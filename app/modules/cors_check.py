import httpx

async def run(target: str) -> dict:
    result = {
        "module": "cors_check",
        "findings": {},
        "severity": "info"
    }

    findings = {
        "cors_enabled": False,
        "allow_origin": None,
        "allow_credentials": False,
        "misconfigured": False,
        "issues": []
    }

    test_origins = [
        "https://evil.com",
        "null",
        f"https://evil.{target}",
    ]

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            for origin in test_origins:
                response = await client.get(
                    f"https://{target}",
                    headers={"Origin": origin},
                    follow_redirects=True
                )
                headers = {k.lower(): v for k, v in response.headers.items()}
                acao = headers.get("access-control-allow-origin")
                acac = headers.get("access-control-allow-credentials", "").lower()

                if acao:
                    findings["cors_enabled"] = True
                    findings["allow_origin"] = acao
                    findings["allow_credentials"] = acac == "true"

                    if acao == "*":
                        findings["misconfigured"] = True
                        findings["issues"].append("Wildcard origin (*) allows any domain")
                        result["severity"] = "high"

                    if acao == origin and origin == "null":
                        findings["misconfigured"] = True
                        findings["issues"].append("Null origin accepted — file:// requests allowed")
                        result["severity"] = "high"

                    if acao == origin and "evil" in origin:
                        findings["misconfigured"] = True
                        findings["issues"].append(f"Arbitrary origin reflected: {origin}")
                        result["severity"] = "critical"

                    if findings["allow_credentials"] and acao == "*":
                        findings["issues"].append("Credentials allowed with wildcard — critical misconfiguration")
                        result["severity"] = "critical"

                    break

    except Exception as e:
        findings["error"] = str(e)

    result["findings"] = findings
    return result
