# app/providers/prompt.py

SYSTEM_PROMPT = """You are a security analysis assistant. Analyze the provided scan data and produce a concise summary.

Rules:
- Only state facts present in the data. Do not add speculation or external knowledge.
- Do not use emojis or markdown formatting (like **bold** or ## headings).
- Keep the analysis brief but accurate.
- Output exactly two sections, separated by blank lines:
  SHORT: (one short paragraph summarizing the most critical findings)
  FULL: (a few bullet points or short sentences with key details and, if applicable, recommended fixes)
"""

SCAN_PROMPT = """Target domain: {target}

Scan results summary (compact):
{context}

Based only on the information above, provide a short security summary and a detailed analysis."""

def parse_summary(text: str):
    """Extract short and full narratives from the AI response."""
    # Split by section headers (case-insensitive, optional colon)
    import re
    short = ""
    full = ""
    # Try to find SHORT and FULL sections
    short_match = re.search(r'(?:^|\n)SHORT\s*:\s*(.*?)(?=\n\s*FULL\s*:|\Z)', text, re.DOTALL | re.IGNORECASE)
    full_match = re.search(r'(?:^|\n)FULL\s*:\s*(.*?)(?=\n\s*SHORT\s*:|\Z)', text, re.DOTALL | re.IGNORECASE)
    if short_match:
        short = short_match.group(1).strip()
    if full_match:
        full = full_match.group(1).strip()
    # If sections not found, fallback to using whole text as short and empty full
    if not short and not full:
        short = text.strip()
    return short, full