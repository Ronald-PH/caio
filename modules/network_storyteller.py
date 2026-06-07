import logging
import re

from flask import Blueprint, jsonify, render_template, request

from modules.ai_client import query_ai_full

logger = logging.getLogger(__name__)
story_bp = Blueprint("network_storyteller", __name__)

SYSTEM_PROMPT = (
    "You are a senior network forensic analyst and incident responder. "
    "Analyze network connection logs and narrate the sequence of events as an "
    "engaging, clear 'attack story' that a SOC analyst or executive can understand."
)

STORY_PROMPT = """Based on the following network connection logs, create a compelling, accurate "attack story":

--- LOGS START ---
{logs}
--- LOGS END ---

Tell the story of what happened. Include:

1. **Attack Timeline**: Chronological sequence of events with timestamps
2. **Initial Access**: How the attacker first gained entry
3. **Lateral Movement**: Which internal systems were pivoted to
4. **C2 Communication**: Beaconing patterns, command servers
5. **Data Exfiltration Indicators**: Large outbound transfers, suspicious destinations
6. **Attacker TTPs**: MITRE ATT&CK techniques observed
7. **Key Assets at Risk**: Critical systems involved
8. **Attack Narrative**: Write a 2-3 paragraph plain-English story of the attack
9. **Defender Actions**: What defenders should have done at each stage

Write in clear, professional language suitable for both technical and non-technical readers."""


def parse_log_format(logs: str) -> dict:
    """Attempt to detect and parse log format."""
    results = {
        "format": "unknown",
        "connections": [],
        "suspicious": []
    }
    
    # Check for Zeek/Bro format
    if "::" in logs and any(x in logs for x in ["Conn", "HTTP", "DNS"]):
        results["format"] = "zeek/bro"
    
    # Check for common column formats
    lines = logs.strip().split('\n')
    for line in lines[:10]:
        # Check for IP:port patterns
        if re.search(r'\d+\.\d+\.\d+\.\d+:\d+', line):
            results["format"] = "tcpdump/netstat"
        
        # Check for comma-separated connection logs
        if re.search(r'\d+\.\d+\.\d+\.\d+,\d+\.\d+\.\d+\.\d+', line):
            results["format"] = "csv/netflow"
    
    # Count external IPs (non-RFC1918)
    private_networks = [
        r'10\.\d+\.\d+\.\d+',
        r'172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+',
        r'192\.168\.\d+\.\d+'
    ]
    
    external_ips = []
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    for ip in re.findall(ip_pattern, logs):
        is_private = any(re.match(net, ip) for net in private_networks)
        if not is_private and ip not in external_ips and ip not in ['0.0.0.0', '255.255.255.255']:
            external_ips.append(ip)
    
    results["suspicious"] = external_ips[:10]
    
    return results


@story_bp.route("/", methods=["GET"])
def story_page():
    return render_template("network_storyteller.html")


@story_bp.route("/tell", methods=["POST"])
def tell_story():
    """Analyze network logs and generate attack narrative."""
    data = request.get_json()
    logs = (data.get("logs") or "").strip()
    provider = data.get("provider", "ollama")
    model = data.get("model", "")
    log_format = data.get("log_format", "auto")

    if not logs:
        return jsonify({"error": "No log data provided."}), 400

    if len(logs) > 50000:
        logs = logs[:50000] + "\n\n[... truncated ...]"

    logger.info("[NetworkStoryteller] Analyzing %d chars of logs", len(logs))

    parsed = parse_log_format(logs)
    
    prompt = STORY_PROMPT.format(
        logs=f"Detected format: {parsed['format']}\nPotentially suspicious external IPs: {', '.join(parsed['suspicious'])}\n\n{logs}"
    )

    result, tokens, cost = query_ai_full(
        prompt, provider=provider, model=model or None, system=SYSTEM_PROMPT
    )

    # Persist to database
    try:
        from database import save_scan
        save_scan(
            target=f"[network] {len(logs)} chars",
            module_type="network_storyteller",
            ai_provider=provider,
            result_text=result,
            tokens_used=tokens,
            cost_estimate=cost,
        )
    except Exception as db_exc:
        logger.warning("DB save failed: %s", db_exc)

    return jsonify({
        "analysis": result,
        "detected_format": parsed["format"],
        "suspicious_ips": parsed["suspicious"],
        "log_length": len(logs),
        "tokens_used": tokens,
        "cost_estimate": cost,
    })