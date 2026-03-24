import httpx
import re

SENSITIVE_PATTERNS = [
    (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})', "API Key"),
    (r'(?i)(secret[_-]?key|secret)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})', "Secret Key"),
    (r'(?i)(access[_-]?token|accesstoken)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})', "Access Token"),
    (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']{6,})["\']', "Password"),
    (r'AIza[0-9A-Za-z\-_]{35}', "Google API Key"),
    (r'sk-[a-zA-Z0-9]{48}', "OpenAI API Key"),
    (r'ghp_[a-zA-Z0-9]{36}', "GitHub Token"),
    (r'(?i)mongodb\+srv://[^\s"\']+', "MongoDB URI"),
    (r'(?i)(aws_access_key_id|aws_secret)\s*[=:]\s*["\']?([A-Z0-9]{20})', "AWS Key"),
]

async def run(target: str) -> dict:
    result = {
        "module": "js_exposure",
        "findings": {},
        "severity": "info"
    }

    findings = {
        "js_files": [],
        "source_maps": [],
        "secrets_found": [],
        "total_js_files": 0
    }

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(f"https://{target}", follow_redirects=True)
            body = response.text

            js_urls = re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', body)
            js_urls = [u if u.startswith("http") else f"https://{target}{u}" for u in js_urls[:10]]

            findings["total_js_files"] = len(js_urls)
            findings["js_files"] = js_urls[:5]

            for js_url in js_urls[:5]:
                try:
                    map_url = js_url + ".map"
                    map_response = await client.get(map_url)
                    if map_response.status_code == 200:
                        findings["source_maps"].append(map_url)
                        result["severity"] = "high"

                    js_response = await client.get(js_url)
                    if js_response.status_code == 200:
                        js_content = js_response.text[:50000]
                        for pattern, label in SENSITIVE_PATTERNS:
                            matches = re.findall(pattern, js_content)
                            if matches:
                                findings["secrets_found"].append({
                                    "type": label,
                                    "file": js_url,
                                    "count": len(matches)
                                })
                                result["severity"] = "critical"
                except Exception:
                    continue

    except Exception as e:
        findings["error"] = str(e)

    result["findings"] = findings
    return result
