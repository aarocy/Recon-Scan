import httpx

WAF_SIGNATURES = {
    "Cloudflare": ["cf-ray", "cloudflare", "__cfduid"],
    "AWS WAF": ["x-amzn-requestid", "awselb"],
    "Akamai": ["akamai", "ak-bmsc"],
    "Imperva": ["incap_ses", "visid_incap", "x-iinfo"],
    "Sucuri": ["x-sucuri-id", "sucuri"],
    "F5 BIG-IP": ["bigipserver", "f5-"],
    "Barracuda": ["barra_counter_session"],
    "ModSecurity": ["mod_security", "modsecurity"],
}

async def run(target: str) -> dict:
    result = {
        "module": "waf_detection",
        "findings": {},
        "severity": "info"
    }

    findings = {
        "waf_detected": False,
        "waf_vendor": None,
        "evidence": [],
        "note": None
    }

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            normal = await client.get(f"https://{target}", follow_redirects=True)
            headers = {k.lower(): v.lower() for k, v in normal.headers.items()}
            header_str = str(headers)

            for vendor, signatures in WAF_SIGNATURES.items():
                for sig in signatures:
                    if sig.lower() in header_str:
                        findings["waf_detected"] = True
                        findings["waf_vendor"] = vendor
                        findings["evidence"].append(sig)
                        break
                if findings["waf_detected"]:
                    break

            malicious = await client.get(
                f"https://{target}/?id=1'%20OR%20'1'='1",
                follow_redirects=True
            )
            if malicious.status_code in [403, 406, 429, 503]:
                findings["note"] = f"Suspicious request blocked with {malicious.status_code} — WAF likely active"
                if not findings["waf_detected"]:
                    findings["waf_detected"] = True
                    findings["waf_vendor"] = "Unknown WAF"

            if not findings["waf_detected"]:
                findings["note"] = "No WAF detected — site may be unprotected"
                result["severity"] = "medium"

    except Exception as e:
        findings["error"] = str(e)

    result["findings"] = findings
    return result

