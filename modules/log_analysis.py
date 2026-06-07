import logging

from flask import Blueprint, jsonify, render_template, request

from modules.ai_client import query_ai_full

logger = logging.getLogger(__name__)
log_bp = Blueprint("log_analysis", __name__)

SYSTEM_PROMPT = (
    "You are a senior SOC analyst and DFIR (Digital Forensics and Incident Response) specialist. "
    "Analyze the provided logs with expert precision. Focus on identifying real threats, not false positives."
)

LOG_ANALYSIS_PROMPT = """Analyze the following log data for security issues:

{logs}

Please provide:
1. **Threat Summary**: Overall assessment (Critical/High/Medium/Low/Informational).
2. **Suspicious Entries**: List each suspicious log line with explanation.
3. **Indicators of Compromise (IOCs)**: Extract IPs, domains, hashes, usernames, file paths.
4. **Attack Patterns**: Identify TTPs (MITRE ATT&CK if applicable).
5. **Timeline**: Reconstruct the sequence of events if possible.
6. **Recommended Actions**: Immediate steps to investigate or mitigate.
7. **False Positive Assessment**: Note any entries that look suspicious but are likely benign.

Format your response with clear headers and bullet points."""


@log_bp.route("/", methods=["GET"])
def log_page():
    return render_template("log_analysis.html")


@log_bp.route("/analyze", methods=["POST"])
def analyze_logs():
    """Analyze pasted log content with chosen LLM and persist result."""
    data = request.get_json()
    logs = (data.get("logs") or "").strip()
    provider = data.get("provider", "ollama")
    model = data.get("model", "")
    log_type = data.get("log_type", "generic")

    if not logs:
        return jsonify({"error": "No log content provided."}), 400

    if len(logs) > 50_000:
        logs = logs[:50_000] + "\n\n[... truncated to 50,000 chars ...]"

    logger.info("[LogAnalysis] Analysing %d chars of %s logs", len(logs), log_type)

    type_hint = {
        "windows_event": "Windows Event Log (XML or text format)",
        "apache":        "Apache/Nginx web server access or error log",
        "syslog":        "Linux syslog / journald output",
        "firewall":      "Firewall / network device log",
        "auth":          "SSH / authentication log (/var/log/auth.log)",
        "generic":       "security log",
    }.get(log_type, "security log")

    prompt = f"Log Type: {type_hint}\n\n" + LOG_ANALYSIS_PROMPT.format(logs=logs)

    result, tokens, cost = query_ai_full(
        prompt, provider=provider, model=model or None, system=SYSTEM_PROMPT
    )

    # Persist to database
    try:
        from database import save_scan
        save_scan(
            target=f"[{log_type}] {len(logs)} chars",
            module_type="log_analysis",
            ai_provider=provider,
            result_text=result,
            tokens_used=tokens,
            cost_estimate=cost,
        )
    except Exception as db_exc:
        logger.warning("DB save failed: %s", db_exc)

    return jsonify({
        "analysis": result,
        "log_length": len(logs),
        "tokens_used": tokens,
        "cost_estimate": cost,
    })
