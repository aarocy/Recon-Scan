import ssl
import socket
from datetime import datetime

async def run(target: str) -> dict:
    result = {
        "module": "ssl_tls",
        "findings": {},
        "severity": "info"
    }

    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(
            socket.socket(socket.AF_INET),
            server_hostname=target
        )
        conn.settimeout(10)
        conn.connect((target, 443))
        cert = conn.getpeercert()
        conn.close()

        expiry_str = cert["notAfter"]
        expiry = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
        days_left = (expiry - datetime.utcnow()).days

        result["findings"] = {
            "subject": dict(x[0] for x in cert["subject"]),
            "issuer": dict(x[0] for x in cert["issuer"]),
            "expires": expiry_str,
            "days_until_expiry": days_left,
            "version": conn.version() if hasattr(conn, 'version') else "TLS"
        }

        if days_left < 7:
            result["severity"] = "critical"
        elif days_left < 30:
            result["severity"] = "high"
        elif days_left < 60:
            result["severity"] = "medium"
        else:
            result["severity"] = "info"

    except ssl.SSLError as e:
        result["severity"] = "critical"
        result["findings"] = {"error": f"SSL error: {str(e)}"}
    except Exception as e:
        result["severity"] = "medium"
        result["findings"] = {"error": str(e)}

    return result
