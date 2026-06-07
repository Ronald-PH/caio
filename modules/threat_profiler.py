import logging
import json

from flask import Blueprint, jsonify, render_template, request

from modules.ai_client import query_ai_full

logger = logging.getLogger(__name__)
threat_bp = Blueprint("threat_profiler", __name__)

SYSTEM_PROMPT = (
    "You are a senior threat intelligence analyst with deep knowledge of APT groups, "
    "cybercriminal organizations, and their TTPs. Correlate indicators with known "
    "threat actor profiles using MITRE ATT&CK framework."
)

PROFILER_PROMPT = """Analyze the following threat indicators and TTPs to identify potential threat actor groups:

{input_data}

Please provide:
1. **Threat Actor Identification**: List likely groups with confidence levels (High/Medium/Low)
2. **MITRE ATT&CK Mapping**: Technique IDs (e.g., T1059) for each observed behavior
3. **Actor Profile Summary**: Typical targets, motivation (espionage/financial/hacktivism)
4. **Key TTPs**: Signature techniques this group is known for
5. **IOC Correlation**: Which indicators match which groups
6. **Confidence Assessment**: Explanation of why certain groups are more likely
7. **Recommendations**: Detection rules and hunting queries based on identified actor

Format with clear headers and bullet points."""


@threat_bp.route("/", methods=["GET"])
def threat_page():
    return render_template("threat_profiler.html")


@threat_bp.route("/profile", methods=["POST"])
def profile_threats():
    """Analyze IOCs/TTPs and identify threat actors."""
    data = request.get_json()
    input_data = (data.get("input_data") or "").strip()
    provider = data.get("provider", "ollama")
    model = data.get("model", "")
    input_type = data.get("input_type", "iocs")

    if not input_data:
        return jsonify({"error": "No input data provided."}), 400

    if len(input_data) > 30000:
        input_data = input_data[:30000] + "\n\n[... truncated ...]"

    logger.info("[ThreatProfiler] Analyzing %d chars of %s data", len(input_data), input_type)

    type_hint = {
        "iocs": "Indicators of Compromise (IPs, domains, hashes, file paths)",
        "ttps": "Tactics, Techniques, and Procedures (describe attacker behavior)",
        "log_snippet": "Log entries showing suspicious activity",
    }.get(input_type, "threat intelligence data")

    prompt = PROFILER_PROMPT.format(input_data=f"Data Type: {type_hint}\n\n{input_data}")

    result, tokens, cost = query_ai_full(
        prompt, provider=provider, model=model or None, system=SYSTEM_PROMPT
    )

    # Persist to database
    try:
        from database import save_scan
        save_scan(
            target=f"[{input_type}] {input_data[:50]}...",
            module_type="threat_profiler",
            ai_provider=provider,
            result_text=result,
            tokens_used=tokens,
            cost_estimate=cost,
        )
    except Exception as db_exc:
        logger.warning("DB save failed: %s", db_exc)

    return jsonify({
        "analysis": result,
        "input_length": len(input_data),
        "tokens_used": tokens,
        "cost_estimate": cost,
    })