import httpx

async def run(target: str) -> dict:
    result = {
        "module": "whois",
        "findings": {},
        "severity": "info"
    }

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(
                f"https://rdap.org/domain/{target}",
                follow_redirects=True
            )
            data = response.json()

            findings = {
                "name": data.get("ldhName", target),
                "status": data.get("status", []),
                "registrar": None,
                "registered": None,
                "expires": None,
                "nameservers": []
            }

            for entity in data.get("entities", []):
                if "registrar" in entity.get("roles", []):
                    vcard = entity.get("vcardArray", [])
                    if vcard:
                        for v in vcard[1]:
                            if v[0] == "fn":
                                findings["registrar"] = v[3]

            for event in data.get("events", []):
                if event["eventAction"] == "registration":
                    findings["registered"] = event["eventDate"]
                elif event["eventAction"] == "expiration":
                    findings["expires"] = event["eventDate"]

            findings["nameservers"] = [
                ns.get("ldhName") for ns in data.get("nameservers", [])
            ]

            result["findings"] = findings

    except Exception as e:
        result["findings"] = {"error": str(e)}
        result["severity"] = "info"

    return result

