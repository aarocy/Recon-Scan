import httpx

HEADERS_TO_CHECK = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]

async def run(target: str) -> dict:
    url = f"https://{target}"
    result = {
        "module": "security_headers",
        "findings": [],
        "severity": "info"
    }

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(url, follow_redirects=True)
            headers = {k.lower(): v for k, v in response.headers.items()}

            missing = []
            present = []

            for header in HEADERS_TO_CHECK:
                if header in headers:
                    present.append({
                        "header": header,
                        "value": headers[header],
                        "status": "present"
                    })
                else:
                    missing.append({
                        "header": header,
                        "status": "missing"
                    })

            result["findings"] = {
                "present": present,
                "missing": missing,
                "url": str(response.url),
                "status_code": response.status_code
            }

            if len(missing) >= 4:
                result["severity"] = "high"
            elif len(missing) >= 2:
                result["severity"] = "medium"
            elif len(missing) >= 1:
                result["severity"] = "low"
            else:
                result["severity"] = "info"

    except httpx.ConnectError:
        result["severity"] = "critical"
        result["findings"] = {"error": "Could not connect to target"}
    except httpx.TimeoutException:
        result["severity"] = "medium"
        result["findings"] = {"error": "Request timed out"}
    except Exception as e:
        result["severity"] = "medium"
        result["findings"] = {"error": str(e)}

    return result
