import logging
import re
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Blueprint, jsonify, render_template, request
from modules.ai_client import query_ai_full

logger = logging.getLogger(__name__)
osint_bp = Blueprint("osint_profiler", __name__)

SYSTEM_PROMPT = (
    "You are a senior OSINT investigator and threat intelligence analyst. "
    "Build comprehensive threat surface profiles from public data sources."
)

PROFILER_PROMPT = """Create a threat intelligence dossier for the target: {target_name}

=== OSINT DATA COLLECTED ===
{osint_data}

=== GITHUB ANALYSIS ===
{github_data}

=== CERTIFICATE TRANSPARENCY ===
{ct_data}

=== SHODAN PATTERNS ===
{shodan_patterns}

=== INTELLIGENCE GAPS ===
{gaps}

Generate a structured threat dossier:

1. **Executive Summary**: High-level risk assessment
2. **Public Footprint**: Domains, subdomains, exposed services
3. **Employee Exposure**: Identified personnel, roles, patterns
4. **Technical Exposure**: GitHub repos, commits, API keys, certificates
5. **Attack Surface**: Most likely entry points
6. **Recommended Countermeasures**: Defensive actions
7. **OSINT Gaps & Recommended Searches**"""


def search_github(target: str) -> dict:
    """Search GitHub for target-related repositories and commits."""
    results = {
        "repos": [],
        "email_commits": [],
        "potential_keys": [],
        "error": None
    }
    
    try:
        # Search repositories
        url = f"https://api.github.com/search/repositories?q={target}&per_page=10"
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            for repo in data.get("items", []):
                results["repos"].append({
                    "name": repo.get("full_name"),
                    "description": repo.get("description", "")[:200],
                    "url": repo.get("html_url"),
                    "stars": repo.get("stargazers_count")
                })
        
        # Search code for potential secrets
        secret_patterns = [
            "api_key", "secret", "password", "token", "private_key",
            "-----BEGIN RSA PRIVATE KEY-----", "AKIA", "sk-"
        ]
        for pattern in secret_patterns:
            url = f"https://api.github.com/search/code?q={target}+{pattern}&per_page=5"
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                for item in resp.json().get("items", []):
                    results["potential_keys"].append({
                        "file": item.get("path"),
                        "repo": item.get("repository", {}).get("full_name"),
                        "pattern": pattern
                    })
    except Exception as e:
        results["error"] = str(e)
    
    return results


def search_certificate_transparency(domain: str) -> list:
    """Query certificate transparency logs for subdomains."""
    subdomains = set()
    try:
        # Use crt.sh
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            for entry in data[:100]:  # Limit to 100 entries
                name = entry.get("name_value", "")
                if name:
                    for sub in name.split('\n'):
                        if domain in sub:
                            subdomains.add(sub.strip())
    except Exception as e:
        logger.warning(f"CT lookup failed: {e}")
    
    return list(subdomains)[:50]


def linkedin_pattern_analysis(target: str) -> dict:
    """Analyze potential LinkedIn exposure patterns without scraping."""
    # This is pattern-based analysis, not active scraping
    patterns = {
        "email_formats": [
            f"first.last@{target}",
            f"first@{target}",
            f"flast@{target}",
            f"firstlast@{target}"
        ],
        "employee_roles": [
            "CISO", "Security Engineer", "IT Director", 
            "DevOps", "System Administrator", "Network Engineer"
        ]
    }
    
    return {
        "suggested_email_formats": patterns["email_formats"],
        "high_value_roles": patterns["employee_roles"],
        "disclaimer": "This is pattern-based analysis. No actual employee data was retrieved."
    }


@osint_bp.route("/", methods=["GET"])
def osint_page():
    return render_template("osint_profiler.html")


@osint_bp.route("/profile", methods=["POST"])
def profile_target():
    data = request.get_json()
    target = (data.get("target") or "").strip()
    target_type = data.get("target_type", "person")  # person or organization
    provider = data.get("provider", "ollama")
    model = data.get("model", "")
    include_github = data.get("include_github", True)
    include_ct = data.get("include_ct", True)

    if not target:
        return jsonify({"error": "No target provided."}), 400

    logger.info(f"[OSINTProfiler] Profiling {target_type}: {target}")

    # Collect OSINT data
    osint_results = {"github": {}, "ct": [], "linkedin_patterns": {}}
    
    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = {}
        
        if include_github:
            futures["github"] = executor.submit(search_github, target)
        
        if include_ct and "." in target:
            futures["ct"] = executor.submit(search_certificate_transparency, target)
        
        futures["linkedin"] = executor.submit(linkedin_pattern_analysis, target)
        
        for name, future in futures.items():
            try:
                osint_results[name] = future.result(timeout=30)
            except Exception as e:
                osint_results[name] = {"error": str(e)}

    # Build OSINT data string for AI
    osint_data = f"""
=== TARGET TYPE ===
{target_type.upper()}: {target}

=== GITHUB INTEL ===
Repositories: {len(osint_results['github'].get('repos', []))} found
Potential leaked keys: {len(osint_results['github'].get('potential_keys', []))}

=== CERTIFICATE TRANSPARENCY ===
Subdomains found: {len(osint_results.get('ct', []))}
Sample: {', '.join(osint_results.get('ct', [])[:10])}

=== EMPLOYEE/RELATED PATTERNS ===
{osint_results['linkedin'].get('suggested_email_formats', [])}
"""

    prompt = PROFILER_PROMPT.format(
        target_name=target,
        osint_data=osint_data,
        github_data=str(osint_results.get("github", {})),
        ct_data="\n".join(osint_results.get("ct", [])[:20]),
        shodan_patterns="Requires Shodan API key for live data",
        gaps="LinkedIn profiles, Shodan data, whois history (requires API keys)"
    )

    result, tokens, cost = query_ai_full(
        prompt, provider=provider, model=model or None, system=SYSTEM_PROMPT
    )

    # Persist to database
    try:
        from database import save_scan
        save_scan(
            target=target,
            module_type="osint_profiler",
            ai_provider=provider,
            result_text=result,
            tokens_used=tokens,
            cost_estimate=cost,
        )
    except Exception as db_exc:
        logger.warning("DB save failed: %s", db_exc)

    return jsonify({
        "analysis": result,
        "osint_summary": {
            "github_repos_found": len(osint_results.get("github", {}).get("repos", [])),
            "ct_subdomains_found": len(osint_results.get("ct", [])),
            "email_patterns": osint_results.get("linkedin", {}).get("suggested_email_formats", [])
        },
        "tokens_used": tokens,
        "cost_estimate": cost,
    })