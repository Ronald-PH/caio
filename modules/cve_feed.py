import logging
import json
import re
from datetime import datetime

import requests
from flask import Blueprint, jsonify, render_template, request

from modules.ai_client import query_ai_full

logger = logging.getLogger(__name__)
cve_bp = Blueprint("cve_feed", __name__)

SYSTEM_PROMPT = (
    "You are a senior vulnerability management analyst. Analyze CVEs in the context "
    "of the user's environment, provide actionable patch priorities, and explain "
    "exploitability and business impact."
)

CVE_PROMPT = """Analyze the following CVE(s) for a production environment:

CVEs to analyze:
{cve_list}

Environment Context (provided by user):
{context}

For each CVE, provide:

1. **Priority Score**: 1-10 (10=patch immediately, 1=low priority) with reasoning
2. **Exploit Status**: Known exploits? (Public/None/Theoretical/Active)
3. **EPSS Score** (if available): Probability of exploitation
4. **Business Impact**: Specific to the user's environment context
5. **Patch Timeline**: Urgency (Immediate/7 days/30 days/Schedule normally)
6. **Workarounds**: Temporary mitigations if patch not available
7. **Technical Details**: In plain English
8. **Detection Methods**: How to identify vulnerable systems

Then provide:
9. **Overall Summary**: Grouped priority recommendations
10. **Action Plan**: What to patch first, second, third

Format with each CVE as a clear section."""


def fetch_cve_details(cve_id: str) -> dict:
    """Fetch CVE details from NVD API."""
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("vulnerabilities"):
                vuln = data["vulnerabilities"][0]["cve"]
                metrics = vuln.get("metrics", {})
                cvss_v3 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {}) if metrics.get("cvssMetricV31") else {}
                cvss_v2 = metrics.get("cvssMetricV2", [{}])[0].get("cvssData", {}) if metrics.get("cvssMetricV2") else {}
                
                # Calculate EPSS-like score from metrics if available
                epss = "Not available"
                if "cvssMetricV31" in metrics:
                    epss = f"CVSS v3.1 Base Score: {cvss_v3.get('baseScore', 'N/A')}"
                
                return {
                    "id": cve_id,
                    "description": vuln.get("descriptions", [{}])[0].get("value", "No description")[:500],
                    "cvss_v3_score": cvss_v3.get("baseScore", "N/A"),
                    "cvss_v3_severity": cvss_v3.get("baseSeverity", "N/A"),
                    "cvss_v2_score": cvss_v2.get("baseScore", "N/A"),
                    "published": vuln.get("published", "Unknown"),
                    "references": [r.get("url", "") for r in vuln.get("references", [])[:5]],
                    "cwe": vuln.get("weaknesses", [{}])[0].get("description", [{}])[0].get("value", "Unknown") if vuln.get("weaknesses") else "Unknown",
                }
        return {"id": cve_id, "error": f"HTTP {resp.status_code}"}
    except Exception as e:
        logger.warning(f"Failed to fetch CVE {cve_id}: {e}")
        return {"id": cve_id, "error": str(e)}


@cve_bp.route("/", methods=["GET"])
def cve_page():
    return render_template("cve_feed.html")


@cve_bp.route("/lookup", methods=["POST"])
def lookup_cves():
    """Look up CVEs and analyze with AI."""
    data = request.get_json()
    cve_input = (data.get("cves") or "").strip()
    context = (data.get("context") or "").strip()
    provider = data.get("provider", "ollama")
    model = data.get("model", "")

    if not cve_input:
        return jsonify({"error": "No CVE IDs provided."}), 400

    # Extract CVE IDs from input
    cve_pattern = r'CVE-\d{4}-\d{4,}'
    cve_ids = list(set(re.findall(cve_pattern, cve_input, re.IGNORECASE)))
    
    if not cve_ids:
        return jsonify({"error": "No valid CVE IDs found (format: CVE-YYYY-XXXXX)"}), 400

    logger.info("[CVEFeed] Looking up %d CVEs: %s", len(cve_ids), ", ".join(cve_ids[:5]))

    # Fetch CVE details
    cve_details = []
    for cve_id in cve_ids[:10]:  # Limit to 10 CVEs per request
        details = fetch_cve_details(cve_id)
        cve_details.append(details)

    # Prepare prompt for AI
    cve_text = "\n\n".join([
        f"--- {d.get('id', 'Unknown')} ---\n"
        f"Description: {d.get('description', 'N/A')}\n"
        f"CVSS v3.1: {d.get('cvss_v3_score', 'N/A')} ({d.get('cvss_v3_severity', 'N/A')})\n"
        f"Published: {d.get('published', 'N/A')}\n"
        f"References: {', '.join(d.get('references', [])[:2])}"
        for d in cve_details if "error" not in d
    ])

    if not cve_text:
        return jsonify({"error": "Failed to fetch CVE details. Check CVE IDs and try again."}), 400

    prompt = CVE_PROMPT.format(
        cve_list=cve_text,
        context=context or "No specific context provided - general enterprise environment with internet-facing and internal systems."
    )

    result, tokens, cost = query_ai_full(
        prompt, provider=provider, model=model or None, system=SYSTEM_PROMPT
    )

    # Persist to database
    try:
        from database import save_scan
        save_scan(
            target=", ".join(cve_ids[:5]),
            module_type="cve_feed",
            ai_provider=provider,
            result_text=result,
            tokens_used=tokens,
            cost_estimate=cost,
        )
    except Exception as db_exc:
        logger.warning("DB save failed: %s", db_exc)

    return jsonify({
        "analysis": result,
        "cves_found": cve_ids,
        "cve_details": cve_details,
        "tokens_used": tokens,
        "cost_estimate": cost,
    })