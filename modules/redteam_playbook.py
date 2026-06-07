import logging
import json

from flask import Blueprint, jsonify, render_template, request

from modules.ai_client import query_ai_full

logger = logging.getLogger(__name__)
playbook_bp = Blueprint("redteam_playbook", __name__)

SYSTEM_PROMPT = (
    "You are a senior red team commander with expertise in adversary emulation, "
    "MITRE ATT&CK frameworks, and security assessment planning. Generate structured, "
    "ethical, and actionable red team engagement plans."
)

PLAYBOOK_PROMPT = """Create a comprehensive Red Team engagement playbook for the following target:

=== TARGET PROFILE ===
Organization Type: {org_type}
Industry: {industry}
Size: {size} employees
Key Assets: {key_assets}
External Footprint: {external_footprint}
Security Posture: {security_posture}
Simulation Goals: {goals}
Duration: {duration}
Constraints: {constraints}

=== ADDITIONAL CONTEXT ===
{additional_context}

Generate a structured playbook with:

## 1. Engagement Overview
- Objectives and success criteria
- Rules of engagement
- Scope boundaries

## 2. Threat Actor Emulation Profile
- APT group to emulate (with reasoning)
- TTPs aligned to MITRE ATT&CK
- Motivations and behaviors

## 3. Attack Phases (Day-by-Day)

### Phase 1: Reconnaissance (Days 1-2)
- External footprint discovery
- OSINT collection methods
- Expected findings

### Phase 2: Initial Access (Day 3)
- Specific attack vectors to test
- Phishing/social engineering scenarios
- Public-facing application testing

### Phase 3: Persistence & C2 (Day 4)
- Implant types and C2 channels
- Persistence mechanisms

### Phase 4: Lateral Movement (Days 5-6)
- Internal network pivoting techniques
- Credential harvesting methods
- Privilege escalation paths

### Phase 5: Objective Completion (Day 7)
- Data exfiltration simulation
- Impact demonstration

## 4. Tools & Commands
- Specific tools to use (Cobalt Strike, Empire, etc.)
- Example commands for key phases

## 5. Detection Opportunities
- What blue team should look for at each phase
- SIEM queries to test

## 6. Reporting Requirements
- What to document
- Deliverable format

## 7. Risk & Contingency
- Potential issues and mitigation

Format as a professional red team engagement plan."""


@playbook_bp.route("/", methods=["GET"])
def playbook_page():
    return render_template("redteam_playbook.html")


@playbook_bp.route("/generate", methods=["POST"])
def generate_playbook():
    """Generate red team playbook based on target profile."""
    data = request.get_json()
    
    org_type = data.get("org_type", "Corporate")
    industry = data.get("industry", "Technology")
    size = data.get("size", "500-1000")
    key_assets = data.get("key_assets", "Customer data, intellectual property, internal systems")
    external_footprint = data.get("external_footprint", "Public website, employee VPN, cloud services (AWS)")
    security_posture = data.get("security_posture", "Standard corporate security with EDR and SIEM")
    goals = data.get("goals", "Test detection capabilities, identify crown jewel vulnerabilities")
    duration = data.get("duration", "5 days")
    constraints = data.get("constraints", "No destructive actions, business hours only")
    additional_context = data.get("additional_context", "")
    
    provider = data.get("provider", "ollama")
    model = data.get("model", "")

    logger.info("[RedTeamPlaybook] Generating playbook for %s in %s industry", org_type, industry)

    prompt = PLAYBOOK_PROMPT.format(
        org_type=org_type,
        industry=industry,
        size=size,
        key_assets=key_assets,
        external_footprint=external_footprint,
        security_posture=security_posture,
        goals=goals,
        duration=duration,
        constraints=constraints,
        additional_context=additional_context or "None provided"
    )

    result, tokens, cost = query_ai_full(
        prompt, provider=provider, model=model or None, system=SYSTEM_PROMPT
    )

    # Persist to database
    try:
        from database import save_scan
        save_scan(
            target=org_type,
            module_type="redteam_playbook",
            ai_provider=provider,
            result_text=result,
            tokens_used=tokens,
            cost_estimate=cost,
        )
    except Exception as db_exc:
        logger.warning("DB save failed: %s", db_exc)

    return jsonify({
        "playbook": result,
        "tokens_used": tokens,
        "cost_estimate": cost,
    })