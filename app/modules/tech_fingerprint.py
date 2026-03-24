import httpx
import re

SIGNATURES = {
    "WordPress": ["wp-content", "wp-includes", "xmlrpc.php"],
    "Drupal": ["Drupal.settings", "/sites/default/files"],
    "Joomla": ["/components/com_", "Joomla!"],
    "React": ["__NEXT_DATA__", "react-dom"],
    "Next.js": ["__NEXT_DATA__", "_next/static"],
    "Vue.js": ["__vue__", "vue-router"],
    "Angular": ["ng-version", "angular.min.js"],
    "Laravel": ["laravel_session", "Laravel"],
    "Django": ["csrfmiddlewaretoken", "django"],
    "Ruby on Rails": ["_rails_", "action_dispatch"],
    "Cloudflare": ["cf-ray", "cloudflare"],
    "AWS": ["x-amz-", "amazonaws.com"],
    "Nginx": ["nginx"],
    "Apache": ["apache"],
}

async def run(target: str) -> dict:
    result = {
        "module": "tech_fingerprint",
        "findings": {},
        "severity": "info"
    }

    findings = {
        "technologies": [],
        "server": None,
        "powered_by": None,
        "cookies": [],
        "cdn": None
    }

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(
                f"https://{target}",
                follow_redirects=True
            )

            headers = {k.lower(): v for k, v in response.headers.items()}
            body = response.text.lower()

            findings["server"] = headers.get("server")
            findings["powered_by"] = headers.get("x-powered-by")

            detected = []
            for tech, signatures in SIGNATURES.items():
                for sig in signatures:
                    if sig.lower() in body or sig.lower() in str(headers):
                        detected.append(tech)
                        break

            findings["technologies"] = list(set(detected))

            cookie_header = headers.get("set-cookie", "")
            if cookie_header:
                findings["cookies"] = [cookie_header[:100]]

            if "cf-ray" in headers or "cloudflare" in str(headers):
                findings["cdn"] = "Cloudflare"
            elif "x-amz-" in str(headers):
                findings["cdn"] = "AWS CloudFront"
            elif "fastly" in str(headers):
                findings["cdn"] = "Fastly"
            elif "akamai" in str(headers):
                findings["cdn"] = "Akamai"

    except Exception as e:
        findings["error"] = str(e)

    result["findings"] = findings
    return result
