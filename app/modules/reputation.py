import httpx
from app.config import settings

async def run(target: str) -> dict:
    result = {
        "module": "reputation",
        "findings": {},
        "severity": "info"
    }

    findings = {
        "virustotal": None,
        "google_safe_browsing": None,
        "phishtank": None,
        "overall_clean": True,
        "flagged_by": []
    }

    async with httpx.AsyncClient(timeout=10) as client:

        try:
            if not settings.virustotal_api_key:
                findings["virustotal"] = {"status": "no api key configured"}
            else:
                vt_response = await client.get(
                    f"https://www.virustotal.com/api/v3/domains/{target}",
                    headers={"x-apikey": settings.virustotal_api_key},
                )
                if vt_response.status_code == 200:
                    vt_data = vt_response.json()
                    stats = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    findings["virustotal"] = {
                        "malicious": malicious,
                        "suspicious": suspicious,
                        "clean": malicious == 0 and suspicious == 0
                    }
                    if malicious > 0 or suspicious > 0:
                        findings["flagged_by"].append("virustotal")
                        findings["overall_clean"] = False
                else:
                    findings["virustotal"] = {"status": f"lookup failed ({vt_response.status_code})"}
        except Exception as e:
            findings["virustotal"] = {"error": str(e)}

        try:
            if not settings.google_safe_browsing_api_key:
                findings["google_safe_browsing"] = {"status": "no api key configured"}
            else:
                gsb_response = await client.post(
                    "https://safebrowsing.googleapis.com/v4/threatMatches:find",
                    params={"key": settings.google_safe_browsing_api_key},
                    json={
                        "client": {"clientId": "reconscan", "clientVersion": "1.0"},
                        "threatInfo": {
                            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                            "platformTypes": ["ANY_PLATFORM"],
                            "threatEntryTypes": ["URL"],
                            "threatEntries": [{"url": f"https://{target}"}]
                        }
                    }
                )
                if gsb_response.status_code == 200:
                    gsb_data = gsb_response.json()
                    matches = gsb_data.get("matches", [])
                    findings["google_safe_browsing"] = {
                        "flagged": len(matches) > 0,
                        "threats": [m.get("threatType") for m in matches]
                    }
                    if matches:
                        findings["flagged_by"].append("google_safe_browsing")
                        findings["overall_clean"] = False
                else:
                    findings["google_safe_browsing"] = {"status": f"lookup failed ({gsb_response.status_code})"}
        except Exception as e:
            findings["google_safe_browsing"] = {"error": str(e)}

        try:
            pt_response = await client.get(
                f"https://checkurl.phishtank.com/checkurl/",
                data={"url": f"https://{target}", "format": "json"},
                headers={"User-Agent": "ReconScan/1.0"}
            )
            if pt_response.status_code == 200:
                pt_data = pt_response.json()
                in_database = pt_data.get("results", {}).get("in_database", False)
                valid = pt_data.get("results", {}).get("valid", False)
                findings["phishtank"] = {
                    "in_database": in_database,
                    "is_phish": valid and in_database
                }
                if in_database and valid:
                    findings["flagged_by"].append("phishtank")
                    findings["overall_clean"] = False
            else:
                findings["phishtank"] = {"status": "unavailable"}
        except Exception as e:
            findings["phishtank"] = {"status": "unavailable"}

    if not findings["overall_clean"]:
        flagged_count = len(findings["flagged_by"])
        if flagged_count >= 2:
            result["severity"] = "critical"
        else:
            result["severity"] = "high"

    result["findings"] = findings
    return result
