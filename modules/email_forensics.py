import logging
import re
import ipaddress
from datetime import datetime
from email import message_from_string
from email.utils import parsedate_to_datetime
from flask import Blueprint, jsonify, render_template, request
from modules.ai_client import query_ai_full

logger = logging.getLogger(__name__)
email_bp = Blueprint("email_forensics", __name__)

SYSTEM_PROMPT = (
    "You are a forensic email analyst and incident responder. Analyze email headers "
    "for spoofing, phishing, and routing anomalies with precision scoring."
)

HEADER_PROMPT = """Analyze these email headers for forensic indicators:

=== RAW HEADERS ===
{headers}

=== PARSED ROUTING ===
Received hops: {hop_count}
Originating IP: {originating_ip}
Authentication results: {auth_results}

=== SPF/DKIM/DMARC ===
{spf_dkim_dmarc}

=== SPOOFING INDICATORS ===
{spoofing_indicators}

Provide:

1. **Legitimacy Score**: 0-100 (0=malicious, 100=legitimate)
2. **Risk Assessment**: Phishing confidence with reasoning
3. **Routing Analysis**: Geographic hops, anomalies, TTL analysis
4. **Infrastructure Identification**: Hosting providers, ASNs, reputation
5. **Attack Indicators**: Spoofing type (display name, domain, reply-to)
6. **Recommendations**: Block rules, user education points
7. **Extracted IOCs**: IPs, domains, email addresses"""


def parse_email_headers(raw_headers: str) -> dict:
    """Parse raw email headers into structured data."""
    result = {
        "from": "",
        "to": "",
        "subject": "",
        "date": "",
        "message_id": "",
        "reply_to": "",
        "return_path": "",
        "received": [],
        "spf": "",
        "dkim": "",
        "dmarc": "",
        "auth_results": "",
        "originating_ip": None
    }
    
    try:
        msg = message_from_string(raw_headers)
        result["from"] = msg.get("From", "")
        result["to"] = msg.get("To", "")
        result["subject"] = msg.get("Subject", "")
        result["date"] = msg.get("Date", "")
        result["message_id"] = msg.get("Message-ID", "")
        result["reply_to"] = msg.get("Reply-To", "")
        result["return_path"] = msg.get("Return-Path", "")
        
        # Parse Authentication-Results
        auth_results = msg.get("Authentication-Results", "")
        result["auth_results"] = auth_results
        
        # Extract SPF/DKIM/DMARC
        if "spf=" in auth_results.lower():
            spf_match = re.search(r'spf=(\w+)', auth_results, re.I)
            result["spf"] = spf_match.group(1) if spf_match else "unknown"
        if "dkim=" in auth_results.lower():
            dkim_match = re.search(r'dkim=(\w+)', auth_results, re.I)
            result["dkim"] = dkim_match.group(1) if dkim_match else "unknown"
        if "dmarc=" in auth_results.lower():
            dmarc_match = re.search(r'dmarc=(\w+)', auth_results, re.I)
            result["dmarc"] = dmarc_match.group(1) if dmarc_match else "unknown"
        
        # Parse Received headers (in reverse order - earliest first)
        received_headers = msg.get_all("Received", [])
        for header in received_headers:
            parsed = parse_received_header(header)
            result["received"].append(parsed)
        
        # Try to extract originating IP from first Received header
        if result["received"]:
            first_hop = result["received"][0]
            if first_hop.get("from_ip"):
                result["originating_ip"] = first_hop["from_ip"]
                
    except Exception as e:
        logger.warning(f"Header parsing error: {e}")
        result["error"] = str(e)
    
    return result


def parse_received_header(header: str) -> dict:
    """Parse a single Received header."""
    result = {"raw": header, "from_ip": None, "from_host": None, "by": None, "with": None, "timestamp": None}
    
    # Extract IP from "from" part: from [192.168.1.1] or from mail.example.com (192.168.1.1)
    ip_pattern = r'from\s+(?:\[?([0-9a-f.:]+)\]?|\S+\s+\(([0-9a-f.:]+)\))'
    ip_match = re.search(ip_pattern, header, re.I)
    if ip_match:
        result["from_ip"] = ip_match.group(1) or ip_match.group(2)
    
    # Extract by server
    by_pattern = r'by\s+(\S+)'
    by_match = re.search(by_pattern, header, re.I)
    if by_match:
        result["by"] = by_match.group(1)
    
    # Extract with protocol
    with_pattern = r'with\s+(\S+)'
    with_match = re.search(with_pattern, header, re.I)
    if with_match:
        result["with"] = with_match.group(1)
    
    return result


def check_spoofing_indicators(parsed: dict) -> list:
    """Identify spoofing indicators."""
    indicators = []
    
    # Check display name mismatch vs actual domain
    from_field = parsed.get("from", "")
    if "<" in from_field and ">" in from_field:
        display_name = from_field.split("<")[0].strip()
        actual_email = from_field.split("<")[1].split(">")[0]
        if display_name and "@" not in display_name and actual_email:
            # Suspicious: display name doesn't match email domain
            indicators.append(f"Display name '{display_name}' differs from actual email '{actual_email}'")
    
    # Check reply-to different from from
    reply_to = parsed.get("reply_to", "")
    from_addr = parsed.get("from", "")
    if reply_to and from_addr:
        reply_to_domain = extract_domain(reply_to)
        from_domain = extract_domain(from_addr)
        if reply_to_domain and from_domain and reply_to_domain != from_domain:
            indicators.append(f"Reply-To domain '{reply_to_domain}' differs from From domain '{from_domain}'")
    
    # Check SPF/DKIM/DMARC
    if parsed.get("spf") == "fail":
        indicators.append("SPF authentication FAILED")
    if parsed.get("dkim") == "fail":
        indicators.append("DKIM signature FAILED")
    if parsed.get("dmarc") == "fail":
        indicators.append("DMARC policy FAILED")
    
    # Check for suspicious TLDs in Return-Path
    return_path = parsed.get("return_path", "")
    if return_path:
        suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".top", ".xyz", ".bid", ".date"]
        for tld in suspicious_tlds:
            if tld in return_path.lower():
                indicators.append(f"Suspicious TLD in Return-Path: {tld}")
    
    return indicators


def extract_domain(email: str) -> str:
    """Extract domain from email address."""
    match = re.search(r'@([a-zA-Z0-9.-]+)', email)
    return match.group(1) if match else ""


@email_bp.route("/", methods=["GET"])
def email_page():
    return render_template("email_forensics.html")


@email_bp.route("/analyze", methods=["POST"])
def analyze_headers():
    data = request.get_json()
    headers = (data.get("headers") or "").strip()
    provider = data.get("provider", "ollama")
    model = data.get("model", "")

    if not headers:
        return jsonify({"error": "No email headers provided."}), 400

    logger.info("[EmailForensics] Analyzing email headers")

    parsed = parse_email_headers(headers)
    spoofing_indicators = check_spoofing_indicators(parsed)
    
    prompt = HEADER_PROMPT.format(
        headers=headers[:5000],
        hop_count=len(parsed.get("received", [])),
        originating_ip=parsed.get("originating_ip", "Unknown"),
        auth_results=parsed.get("auth_results", "None"),
        spf_dkim_dmarc=f"SPF: {parsed.get('spf', 'unknown')}, DKIM: {parsed.get('dkim', 'unknown')}, DMARC: {parsed.get('dmarc', 'unknown')}",
        spoofing_indicators="\n".join(spoofing_indicators) or "None detected"
    )

    result, tokens, cost = query_ai_full(
        prompt, provider=provider, model=model or None, system=SYSTEM_PROMPT
    )

    # Persist to database
    try:
        from database import save_scan
        save_scan(
            target=parsed.get("from", "unknown")[:100],
            module_type="email_forensics",
            ai_provider=provider,
            result_text=result,
            tokens_used=tokens,
            cost_estimate=cost,
        )
    except Exception as db_exc:
        logger.warning("DB save failed: %s", db_exc)

    return jsonify({
        "analysis": result,
        "parsed_headers": parsed,
        "spoofing_indicators": spoofing_indicators,
        "tokens_used": tokens,
        "cost_estimate": cost,
    })