from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from io import BytesIO
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, Preformatted, SimpleDocTemplate, Spacer, Table, TableStyle


MODULE_LABELS = {
    "security_headers": "Security Headers",
    "ssl_tls": "SSL / TLS",
    "dns_email": "DNS & Email Auth",
    "whois": "WHOIS",
    "robots_sitemap": "Robots & Sitemap",
    "subdomains": "Subdomain Enumeration",
    "tech_fingerprint": "Tech Fingerprint",
    "waf_detection": "WAF Detection",
    "cors_check": "CORS Check",
    "cookie_security": "Cookie Security",
    "js_exposure": "JS Exposure",
    "directory_exposure": "Directory Exposure",
    "reputation": "Reputation",
}

SEVERITY_COLORS = {
    "critical": colors.HexColor("#5A1111"),
    "high": colors.HexColor("#7A2F13"),
    "medium": colors.HexColor("#6D5A0B"),
    "low": colors.HexColor("#174D1A"),
    "info": colors.HexColor("#243447"),
}


def _safe_text(value: Any) -> str:
    text = str(value) if value is not None else ""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _severity_snapshot(results: list[dict[str, Any]]) -> tuple[int, int, int, int, int]:
    counter = Counter((r.get("severity") or "info").lower() for r in results)
    return (
        counter.get("critical", 0),
        counter.get("high", 0),
        counter.get("medium", 0),
        counter.get("low", 0),
        counter.get("info", 0),
    )


def _result_details(raw_data: Any) -> str:
    if raw_data is None:
        return "No details were captured for this module."
    if isinstance(raw_data, (dict, list)):
        return json.dumps(raw_data, indent=2, ensure_ascii=True)
    return str(raw_data)


def build_scan_pdf(scan: dict[str, Any], results: list[dict[str, Any]], summary: dict[str, Any] | None) -> bytes:
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=LETTER,
        leftMargin=0.7 * inch,
        rightMargin=0.7 * inch,
        topMargin=0.65 * inch,
        bottomMargin=0.65 * inch,
        title=f"ReconScan Report - {scan.get('target_domain', 'unknown-target')}",
        author="ReconScan",
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "TitleStyle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=22,
        textColor=colors.HexColor("#0F172A"),
        spaceAfter=10,
    )
    meta_style = ParagraphStyle(
        "MetaStyle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        textColor=colors.HexColor("#334155"),
        spaceAfter=4,
    )
    h_style = ParagraphStyle(
        "HeaderStyle",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        textColor=colors.HexColor("#111827"),
        spaceBefore=12,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "BodyStyle",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#1F2937"),
    )
    mono_style = ParagraphStyle(
        "MonoStyle",
        parent=styles["Code"],
        fontName="Courier",
        fontSize=8.2,
        leading=10.4,
        textColor=colors.HexColor("#0B1324"),
    )

    target = scan.get("target_domain", "unknown-target")
    created_at = scan.get("created_at", "")
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    critical, high, medium, low, info = _severity_snapshot(results)

    flow = [
        Paragraph("ReconScan Security Report", title_style),
        Paragraph(f"<b>Target:</b> {_safe_text(target)}", meta_style),
        Paragraph(f"<b>Scan ID:</b> {_safe_text(scan.get('id', 'n/a'))}", meta_style),
        Paragraph(f"<b>Scan Created:</b> {_safe_text(created_at)}", meta_style),
        Paragraph(f"<b>Report Generated:</b> {_safe_text(generated_at)}", meta_style),
        Spacer(1, 10),
        Paragraph("Executive Summary", h_style),
    ]

    if summary and (summary.get("short_narrative") or summary.get("full_narrative")):
        short = summary.get("short_narrative") or ""
        full = summary.get("full_narrative") or short
        model = summary.get("model_used") or "unknown-model"
        provider = summary.get("provider") or "unknown-provider"
        flow.append(Paragraph(_safe_text(short), body_style))
        flow.append(Spacer(1, 7))
        flow.append(Paragraph(f"<b>AI Provider:</b> {_safe_text(provider)} · <b>Model:</b> {_safe_text(model)}", meta_style))
        flow.append(Paragraph(_safe_text(full).replace("\n", "<br/>"), body_style))
    else:
        flow.append(Paragraph("No AI summary was available for this scan.", body_style))

    flow.extend(
        [
            Spacer(1, 10),
            Paragraph("Severity Snapshot", h_style),
        ]
    )

    snapshot_table = Table(
        [
            ["Critical", "High", "Medium", "Low", "Info"],
            [str(critical), str(high), str(medium), str(low), str(info)],
        ],
        colWidths=[1.05 * inch] * 5,
        hAlign="LEFT",
    )
    snapshot_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F172A")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 9),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("GRID", (0, 0), (-1, -1), 0.6, colors.HexColor("#CBD5E1")),
                ("FONTNAME", (0, 1), (-1, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 1), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    flow.append(snapshot_table)

    flow.extend([Spacer(1, 12), Paragraph("Module Findings", h_style)])

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_results = sorted(results, key=lambda r: severity_order.get((r.get("severity") or "info").lower(), 5))
    if not sorted_results:
        flow.append(Paragraph("No module records were available for this scan.", body_style))
    else:
        for idx, result in enumerate(sorted_results, start=1):
            module_key = result.get("module", "unknown_module")
            module_name = MODULE_LABELS.get(module_key, module_key)
            severity = (result.get("severity") or "info").lower()
            status = result.get("status") or "unknown"
            details = _result_details(result.get("raw_data"))

            header_table = Table(
                [
                    [f"{idx}. {module_name}", severity.upper(), status.upper()],
                ],
                colWidths=[3.8 * inch, 1.05 * inch, 1.3 * inch],
                hAlign="LEFT",
            )
            header_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#E2E8F0")),
                        ("BACKGROUND", (1, 0), (1, 0), SEVERITY_COLORS.get(severity, SEVERITY_COLORS["info"])),
                        ("BACKGROUND", (2, 0), (2, 0), colors.HexColor("#E5E7EB")),
                        ("TEXTCOLOR", (1, 0), (1, 0), colors.white),
                        ("TEXTCOLOR", (0, 0), (0, 0), colors.HexColor("#111827")),
                        ("TEXTCOLOR", (2, 0), (2, 0), colors.HexColor("#111827")),
                        ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                        ("ALIGN", (1, 0), (2, 0), "CENTER"),
                        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                        ("GRID", (0, 0), (-1, -1), 0.6, colors.HexColor("#CBD5E1")),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                        ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ]
                )
            )
            flow.append(header_table)
            flow.append(Spacer(1, 4))
            flow.append(Preformatted(details[:2500], style=mono_style))
            flow.append(Spacer(1, 8))

    doc.build(flow)
    return buffer.getvalue()
