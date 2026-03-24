import httpx

async def run(target: str) -> dict:
    result = {
        "module": "subdomains",
        "findings": {},
        "severity": "info"
    }

    findings = {
        "subdomains": [],
        "total": 0,
        "sources": []
    }

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.get(
                f"https://crt.sh/?q=%.{target}&output=json",
                follow_redirects=True
            )
            if response.status_code == 200:
                data = response.json()
                subdomains = set()
                for entry in data:
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lower()
                        if sub.endswith(target) and sub != target:
                            subdomains.add(sub)

                findings["subdomains"] = sorted(list(subdomains))
                findings["total"] = len(subdomains)
                findings["sources"] = ["crt.sh"]

                if len(subdomains) > 50:
                    result["severity"] = "medium"
                elif len(subdomains) > 20:
                    result["severity"] = "low"

    except Exception as e:
        findings["error"] = str(e)

    result["findings"] = findings
    return result
