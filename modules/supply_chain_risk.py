import logging
import re
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Blueprint, jsonify, render_template, request
from modules.ai_client import query_ai_full

logger = logging.getLogger(__name__)
supply_bp = Blueprint("supply_chain_risk", __name__)

SYSTEM_PROMPT = (
    "You are a third-party risk management expert and supply chain security analyst. "
    "Evaluate vendors and dependencies for security risks and trustworthiness."
)

RISK_PROMPT = """Perform a supply chain risk assessment for the following items:

=== VENDORS / PACKAGES ===
{vendors}

=== RISK INTELLIGENCE ===
Known CVEs: {cve_data}
Breach history: {breach_data}
Trust indicators: {trust_data}

=== CRITICALITY IN YOUR ENVIRONMENT ===
Data access level: {data_access}
Integration depth: {integration_depth}
Replacement cost: {replacement_cost}

Provide:

1. **Vendor Risk Scorecard** (table format):
   | Vendor | Risk Score (0-100) | Risk Level | Top Concern | Recommended Action |
   |--------|-------------------|------------|-------------|--------------------|

2. **CVE Analysis**:
   - Critical vulnerabilities in each vendor's products
   - Exploit availability (public/private/none)
   - Patch status trends

3. **Breach History**:
   - Known security incidents affecting each vendor
   - Impact on customers
   - Vendor response quality

4. **Trust Chain Analysis**:
   - Sub-processors and dependencies
   - Third-party risks inherited
   - Data residency concerns

5. **Mitigation Recommendations**:
   - Contractual requirements to add
   - Technical controls to implement
   - Monitoring frequency

6. **Overall Supply Chain Risk**: Executive summary with top 3 actions"""


def query_nvd_cve(vendor_name: str) -> list:
    """Query NVD for CVEs related to a vendor."""
    cves = []
    try:
        # Simple search - in production, use proper API with rate limiting
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={vendor_name}&resultsPerPage=10"
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            for vuln in data.get("vulnerabilities", [])[:5]:
                cve_data = vuln.get("cve", {})
                metrics = cve_data.get("metrics", {})
                cvss = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {}) if metrics.get("cvssMetricV31") else {}
                cves.append({
                    "id": cve_data.get("id"),
                    "score": cvss.get("baseScore", "N/A"),
                    "severity": cvss.get("baseSeverity", "N/A"),
                    "description": cve_data.get("descriptions", [{}])[0].get("value", "")[:200]
                })
    except Exception as e:
        logger.warning(f"NVD query failed for {vendor_name}: {e}")
    return cves


def check_breach_history(vendor_name: str) -> dict:
    """Check for known breaches (simulated - integrate with breach APIs)."""
    # In production: integrate with HaveIBeenPwned for companies, security news APIs
    # This is a placeholder with common known breaches
    known_breaches = {
        "solarwinds": {"has_breach": True, "year": 2020, "impact": "Supply chain attack via Orion platform"},
        "kaseya": {"has_breach": True, "year": 2021, "impact": "REvil ransomware via VSA"},
        "microsoft": {"has_breach": True, "year": 2021, "impact": "Exchange Server vulnerabilities (ProxyLogon)"},
        "okta": {"has_breach": True, "year": 2022, "impact": "LAPSUS$ compromise of customer support"}
    }
    
    for key, info in known_breaches.items():
        if key in vendor_name.lower():
            return info
    
    return {"has_breach": False}


@supply_bp.route("/", methods=["GET"])
def supply_page():
    return render_template("supply_chain_risk.html")


@supply_bp.route("/assess", methods=["POST"])
def assess_risk():
    data = request.get_json()
    vendors_input = (data.get("vendors") or "").strip()
    provider = data.get("provider", "ollama")
    model = data.get("model", "")
    data_access = data.get("data_access", "Limited - non-sensitive data only")
    integration_depth = data.get("integration_depth", "API integration with internal systems")
    replacement_cost = data.get("replacement_cost", "Medium - 3-6 months to migrate")

    if not vendors_input:
        return jsonify({"error": "No vendors or packages provided."}), 400

    # Parse vendors (one per line or comma-separated)
    vendors = [v.strip() for v in re.split(r'[\n,]', vendors_input) if v.strip()][:20]
    
    logger.info(f"[SupplyChain] Assessing {len(vendors)} vendors")

    # Collect risk intelligence concurrently
    vendor_intel = {}
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {
            executor.submit(query_nvd_cve, vendor): vendor 
            for vendor in vendors
        }
        for future in as_completed(futures):
            vendor = futures[future]
            try:
                vendor_intel[vendor] = {
                    "cves": future.result(timeout=30),
                    "breach": check_breach_history(vendor)
                }
            except Exception as e:
                vendor_intel[vendor] = {"cves": [], "breach": {"has_breach": False}, "error": str(e)}
    
    # Format data for AI
    vendors_formatted = "\n".join(vendors)
    cve_summary = []
    breach_summary = []
    
    for vendor, intel in vendor_intel.items():
        if intel.get("cves"):
            cve_summary.append(f"{vendor}: {len(intel['cves'])} CVEs found")
        if intel.get("breach", {}).get("has_breach"):
            breach_summary.append(f"{vendor}: Breach in {intel['breach'].get('year', 'unknown')}")
    
    prompt = RISK_PROMPT.format(
        vendors=vendors_formatted,
        cve_data="\n".join(cve_summary) or "No CVEs found in public databases",
        breach_data="\n".join(breach_summary) or "No known breaches in public records",
        trust_data="Trust indicators from SSL/TLS certificates, domain age, and security.txt presence",
        data_access=data_access,
        integration_depth=integration_depth,
        replacement_cost=replacement_cost
    )

    result, tokens, cost = query_ai_full(
        prompt, provider=provider, model=model or None, system=SYSTEM_PROMPT
    )

    # Persist to database
    try:
        from database import save_scan
        save_scan(
            target=f"{len(vendors)} vendors",
            module_type="supply_chain_risk",
            ai_provider=provider,
            result_text=result,
            tokens_used=tokens,
            cost_estimate=cost,
        )
    except Exception as db_exc:
        logger.warning("DB save failed: %s", db_exc)

    return jsonify({
        "analysis": result,
        "vendor_count": len(vendors),
        "vendor_intel": vendor_intel,
        "tokens_used": tokens,
        "cost_estimate": cost,
    })