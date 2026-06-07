import logging
import base64
import re
from urllib.parse import unquote

from flask import Blueprint, jsonify, render_template, request

from modules.ai_client import query_ai_full

logger = logging.getLogger(__name__)
payload_bp = Blueprint("payload_dna", __name__)

SYSTEM_PROMPT = (
    "You are a senior malware analyst and reverse engineer. Analyze suspicious code, "
    "scripts, and encoded payloads for malicious intent. Identify obfuscation techniques "
    "and rate threat severity."
)

DNA_PROMPT = """Perform a deep DNA-style analysis of the following suspicious payload:

--- PAYLOAD START ---
{payload}
--- PAYLOAD END ---

Deobfuscation Notes:
{deobfuscated}

Provide:
1. **Malice Score**: 0-100 (0=benign, 100=critical malware) with rating (Benign/Suspicious/Malicious/Critical)
2. **Payload Classification**: Type (Ransomware/Stealer/Shellcode/Downloader/Backdoor/RAT/Beacon/Other)
3. **Deobfuscation Results**: Original encoding/obfuscation methods detected and decoded form
4. **Key Indicators**: IPs, domains, URLs, registry keys, file paths, mutexes, process names
5. **Behavior Analysis**: What the payload attempts to do (persistence, C2, lateral movement, etc.)
6. **Suspicious Patterns**: Anti-sandbox, AMSI bypass, process injection, etc.
7. **Extracted Strings**: All meaningful strings extracted
8. **Family/Group Attribution**: Known malware family if recognizable
9. **Recommendations**: YARA rules, detection methods, sandbox observations

Format with clear headers and severity badges."""


def deobfuscate_payload(payload: str) -> dict:
    """Attempt to deobfuscate common encoding techniques."""
    results = {
        "original": payload[:500],
        "detected_encodings": [],
        "decoded": "",
        "notes": []
    }
    
    # Try base64 decode
    try:
        # Remove whitespace and try decode
        clean = re.sub(r'\s+', '', payload)
        decoded = base64.b64decode(clean).decode('utf-8', errors='replace')
        if len(decoded) > 10 and decoded != payload:
            results["detected_encodings"].append("Base64")
            results["decoded"] = decoded[:1000]
            results["notes"].append("Base64 decoding successful")
    except Exception:
        pass
    
    # Try URL decode
    try:
        decoded = unquote(payload)
        if decoded != payload:
            results["detected_encodings"].append("URL Encoding")
            if not results["decoded"]:
                results["decoded"] = decoded[:1000]
            results["notes"].append("URL encoding detected")
    except Exception:
        pass
    
    # Check for hex strings
    hex_pattern = r'[0-9A-Fa-f]{32,}'
    hex_matches = re.findall(hex_pattern, payload)
    if hex_matches:
        results["detected_encodings"].append("Hex string detected")
        results["notes"].append(f"Found {len(hex_matches)} potential hex strings")
    
    # PowerShell detection
    if "powershell" in payload.lower() or "-enc" in payload.lower() or "-e " in payload.lower():
        results["detected_encodings"].append("PowerShell")
        results["notes"].append("PowerShell encoded command detected")
        
        # Try to extract base64 from PowerShell
        b64_pattern = r'-e[nc]?\s+([A-Za-z0-9+/=]+)'
        b64_match = re.search(b64_pattern, payload, re.IGNORECASE)
        if b64_match:
            try:
                ps_decoded = base64.b64decode(b64_match.group(1)).decode('utf-16le', errors='replace')
                results["decoded"] = ps_decoded[:1000]
                results["notes"].append("PowerShell base64 decoded")
            except Exception:
                pass
    
    return results


@payload_bp.route("/", methods=["GET"])
def payload_page():
    return render_template("payload_dna.html")


@payload_bp.route("/analyze", methods=["POST"])
def analyze_payload():
    """Analyze suspicious payload for malicious intent."""
    data = request.get_json()
    payload = (data.get("payload") or "").strip()
    provider = data.get("provider", "ollama")
    model = data.get("model", "")
    payload_type = data.get("payload_type", "auto")

    if not payload:
        return jsonify({"error": "No payload provided."}), 400

    if len(payload) > 50000:
        payload = payload[:50000] + "\n\n[... truncated ...]"

    logger.info("[PayloadDNA] Analyzing %d chars of payload", len(payload))

    # Attempt deobfuscation
    deobfuscated = deobfuscate_payload(payload)
    
    prompt = DNA_PROMPT.format(
        payload=payload,
        deobfuscated=f"Encodings: {', '.join(deobfuscated['detected_encodings']) or 'None detected'}\nDecoded: {deobfuscated['decoded'] or 'N/A'}\nNotes: {', '.join(deobfuscated['notes']) or 'None'}"
    )

    result, tokens, cost = query_ai_full(
        prompt, provider=provider, model=model or None, system=SYSTEM_PROMPT
    )

    # Persist to database
    try:
        from database import save_scan
        save_scan(
            target=f"[{payload_type}] {payload[:50]}...",
            module_type="payload_dna",
            ai_provider=provider,
            result_text=result,
            tokens_used=tokens,
            cost_estimate=cost,
        )
    except Exception as db_exc:
        logger.warning("DB save failed: %s", db_exc)

    return jsonify({
        "analysis": result,
        "deobfuscation": deobfuscated,
        "payload_length": len(payload),
        "tokens_used": tokens,
        "cost_estimate": cost,
    })