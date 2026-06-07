import logging
import re
from flask import Blueprint, jsonify, render_template, request
from modules.ai_client import query_ai_full

logger = logging.getLogger(__name__)
siem_bp = Blueprint("siem_rule_generator", __name__)

SYSTEM_PROMPT = (
    "You are a senior detection engineer and security content developer. "
    "Convert attack descriptions into high-quality detection rules across multiple SIEM formats."
)

RULE_GEN_PROMPT = """Generate detection rules for the following attack scenario:

=== ATTACK DESCRIPTION ===
{attack_description}

=== ATTACK TTPs (if provided) ===
{ttps}

=== TARGET ENVIRONMENT ===
{environment}

Generate rules in the following formats:

## 1. SIGMA Rule (YAML)
- Use proper Sigma syntax with detection and condition sections
- Include logsource definition (e.g., Windows, Linux, Network)
- Add relevant MITRE ATT&CK tags

## 2. Splunk SPL
- Production-ready search query
- Include time range recommendations (e.g., earliest=-7d)
- Add comments explaining each part
- Suggest statistical correlations if applicable

## 3. KQL (Microsoft Sentinel / Defender)
- Optimized Kusto Query Language
- Include let statements for parameters
- Add timestamp filtering

## 4. Suricata / Snort
- Network-based detection rule
- Include proper protocol specification
- Add metadata and reference tags

## 5. Detection Summary Table
| Format | Rule Name | Detection Logic | False Positive Risk |
|--------|-----------|-----------------|---------------------|
| Sigma | ... | ... | Low/Med/High |
| SPL | ... | ... | Low/Med/High |
| KQL | ... | ... | Low/Med/High |
| Suricata | ... | ... | Low/Med/High |

## 6. Testing Notes
- Sample commands to test the rule
- Expected alerts
- Potential blindspots"""


# Common MITRE ATT&CK technique descriptions
MITRE_MAPPINGS = {
    "T1059": "Command and Scripting Interpreter",
    "T1059.001": "PowerShell",
    "T1059.003": "Windows Command Shell",
    "T1071": "Application Layer Protocol",
    "T1071.001": "Web Protocols",
    "T1041": "Exfiltration Over C2 Channel",
    "T1027": "Obfuscated Files or Info",
    "T1547": "Boot or Logon Autostart Execution",
    "T1547.001": "Registry Run Keys",
    "T1566": "Phishing",
    "T1566.002": "Spearphishing Attachment",
    "T1133": "External Remote Services",
    "T1486": "Data Encrypted for Impact"
}


def extract_techniques(description: str) -> list:
    """Extract potential MITRE ATT&CK techniques from description."""
    found = []
    for tech_id, name in MITRE_MAPPINGS.items():
        if name.lower() in description.lower() or tech_id in description:
            found.append(tech_id)
    return found


def generate_rule_snippet(description: str, format_type: str) -> str:
    """Generate a basic rule snippet as fallback."""
    snippets = {
        "sigma": f"""title: Detection Rule for {description[:50]}
status: experimental
description: Detects {description}
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4688
        CommandLine|contains: 'suspicious_pattern'
    condition: selection
level: medium
tags:
    - attack.persistence
    - attack.t1547""",
        
        "splunk": f"""index=windows sourcetype=WinEventLog:Security EventCode=4688
| search CommandLine="*suspicious_pattern*"
| table _time, host, user, CommandLine
| sort - _time
| comment("Detects {description}")""",
        
        "kql": f"""SecurityEvent
| where EventID == 4688
| where CommandLine contains "suspicious_pattern"
| project TimeGenerated, Computer, Account, CommandLine
| sort by TimeGenerated desc
// Detects {description}""",
        
        "suricata": f"""alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"SUSPICIOUS {description[:30]}";
    flow:established,to_server;
    content:"suspicious_pattern"; nocase;
    classtype:attempted-recon;
    sid:1000001; rev:1;)"""
    }
    return snippets.get(format_type, "Rule generation requires AI processing.")


@siem_bp.route("/", methods=["GET"])
def siem_page():
    return render_template("siem_rule_generator.html")


@siem_bp.route("/generate", methods=["POST"])
def generate_rules():
    data = request.get_json()
    attack_description = (data.get("attack_description") or "").strip()
    ttps = data.get("ttps", "")
    environment = data.get("environment", "Windows Enterprise with EDR")
    provider = data.get("provider", "ollama")
    model = data.get("model", "")

    if not attack_description:
        return jsonify({"error": "No attack description provided."}), 400

    logger.info(f"[SIEMGen] Generating rules for: {attack_description[:100]}")

    # Extract potential MITRE techniques
    techniques = extract_techniques(attack_description)
    ttp_context = f"Identified techniques: {', '.join(techniques)}\nAdditional TTPs: {ttps}" if techniques else ttps

    prompt = RULE_GEN_PROMPT.format(
        attack_description=attack_description,
        ttps=ttp_context if ttps else "None provided - infer from description",
        environment=environment
    )

    result, tokens, cost = query_ai_full(
        prompt, provider=provider, model=model or None, system=SYSTEM_PROMPT
    )

    # Parse result into sections for UI display
    sections = {}
    current_section = None
    for line in result.split('\n'):
        if line.startswith('## 1.') or 'SIGMA' in line:
            current_section = 'sigma'
            sections[current_section] = []
        elif line.startswith('## 2.') or 'Splunk' in line:
            current_section = 'splunk'
            sections[current_section] = []
        elif line.startswith('## 3.') or 'KQL' in line:
            current_section = 'kql'
            sections[current_section] = []
        elif line.startswith('## 4.') or 'Suricata' in line:
            current_section = 'suricata'
            sections[current_section] = []
        elif current_section and current_section in sections:
            sections[current_section].append(line)
        elif line.startswith('## 5.') or 'Summary' in line:
            current_section = 'summary'
            sections[current_section] = []
        elif current_section == 'summary':
            sections[current_section].append(line)
    
    # Format sections
    formatted_sections = {}
    for k, v in sections.items():
        formatted_sections[k] = '\n'.join(v) if v else f"### {k.upper()} Rule\n{generate_rule_snippet(attack_description, k)}"

    # Persist to database
    try:
        from database import save_scan
        save_scan(
            target=attack_description[:100],
            module_type="siem_rule_generator",
            ai_provider=provider,
            result_text=result,
            tokens_used=tokens,
            cost_estimate=cost,
        )
    except Exception as db_exc:
        logger.warning("DB save failed: %s", db_exc)

    return jsonify({
        "full_response": result,
        "sigma_rule": formatted_sections.get('sigma', generate_rule_snippet(attack_description, 'sigma')),
        "splunk_rule": formatted_sections.get('splunk', generate_rule_snippet(attack_description, 'splunk')),
        "kql_rule": formatted_sections.get('kql', generate_rule_snippet(attack_description, 'kql')),
        "suricata_rule": formatted_sections.get('suricata', generate_rule_snippet(attack_description, 'suricata')),
        "techniques_detected": techniques,
        "tokens_used": tokens,
        "cost_estimate": cost,
    })