import dns.resolver

async def run(target: str) -> dict:
    result = {
        "module": "dns_email",
        "findings": {},
        "severity": "info"
    }

    findings = {}
    missing = []

    try:
        mx = dns.resolver.resolve(target, "MX")
        findings["mx"] = [str(r.exchange) for r in mx]
    except Exception:
        findings["mx"] = []
        missing.append("MX")

    try:
        txt = dns.resolver.resolve(target, "TXT")
        txt_records = [r.to_text() for r in txt]
        spf = [r for r in txt_records if "v=spf1" in r]
        findings["spf"] = spf[0] if spf else None
        if not spf:
            missing.append("SPF")
    except Exception:
        findings["spf"] = None
        missing.append("SPF")

    try:
        dmarc = dns.resolver.resolve(f"_dmarc.{target}", "TXT")
        findings["dmarc"] = dmarc[0].to_text()
    except Exception:
        findings["dmarc"] = None
        missing.append("DMARC")

    try:
        a = dns.resolver.resolve(target, "A")
        findings["a_records"] = [r.address for r in a]
    except Exception:
        findings["a_records"] = []

    findings["missing"] = missing

    if "DMARC" in missing and "SPF" in missing:
        result["severity"] = "critical"
    elif "DMARC" in missing or "SPF" in missing:
        result["severity"] = "high"
    elif missing:
        result["severity"] = "medium"

    result["findings"] = findings
    return result
