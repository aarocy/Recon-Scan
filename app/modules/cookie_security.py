import httpx

async def run(target: str) -> dict:
    result = {
        "module": "cookie_security",
        "findings": {},
        "severity": "info"
    }

    findings = {
        "cookies": [],
        "issues": [],
        "total": 0
    }

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(
                f"https://{target}",
                follow_redirects=True
            )

            cookies = response.cookies
            set_cookie_headers = response.headers.get_list("set-cookie") if hasattr(response.headers, 'get_list') else [response.headers.get("set-cookie", "")]

            for cookie_str in set_cookie_headers:
                if not cookie_str:
                    continue

                cookie_analysis = {
                    "raw": cookie_str[:200],
                    "secure": "secure" in cookie_str.lower(),
                    "httponly": "httponly" in cookie_str.lower(),
                    "samesite": None,
                    "issues": []
                }

                if "samesite=strict" in cookie_str.lower():
                    cookie_analysis["samesite"] = "Strict"
                elif "samesite=lax" in cookie_str.lower():
                    cookie_analysis["samesite"] = "Lax"
                elif "samesite=none" in cookie_str.lower():
                    cookie_analysis["samesite"] = "None"

                if not cookie_analysis["secure"]:
                    cookie_analysis["issues"].append("Missing Secure flag — cookie sent over HTTP")
                if not cookie_analysis["httponly"]:
                    cookie_analysis["issues"].append("Missing HttpOnly flag — accessible via JavaScript")
                if not cookie_analysis["samesite"]:
                    cookie_analysis["issues"].append("Missing SameSite attribute — CSRF risk")
                if cookie_analysis["samesite"] == "None" and not cookie_analysis["secure"]:
                    cookie_analysis["issues"].append("SameSite=None requires Secure flag")

                findings["cookies"].append(cookie_analysis)
                findings["issues"].extend(cookie_analysis["issues"])

            findings["total"] = len(findings["cookies"])

            critical_issues = [i for i in findings["issues"] if "HttpOnly" in i or "Secure" in i]
            if len(critical_issues) >= 3:
                result["severity"] = "high"
            elif len(critical_issues) >= 1:
                result["severity"] = "medium"

    except Exception as e:
        findings["error"] = str(e)

    result["findings"] = findings
    return result
