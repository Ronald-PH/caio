import logging

from flask import Blueprint, jsonify, render_template, request, session

from modules.ai_client import query_ai

logger = logging.getLogger(__name__)
chat_bp = Blueprint("chat", __name__)

CYBER_SYSTEM_PROMPT = """You are CAIO-IR, an elite cybersecurity incident response AI assistant with expertise in:

- Digital Forensics & Incident Response (DFIR)
- Threat Hunting & Intelligence (MITRE ATT&CK, kill chain)
- Malware Analysis & Reverse Engineering
- Network Security & Traffic Analysis
- Windows/Linux/macOS forensics
- Cloud Security (AWS, Azure, GCP)
- SIEM, EDR, and SOC operations
- Vulnerability Management & Exploitation
- Penetration Testing & Red Team TTPs
- Compliance (NIST, ISO 27001, PCI-DSS, GDPR)

Provide detailed, accurate, and actionable security guidance. When relevant:
- Reference specific tools (Sysinternals, Volatility, Wireshark, etc.)
- Cite MITRE ATT&CK technique IDs
- Provide exact commands and scripts (clearly labeled for OS)
- Flag legal and ethical considerations
- Suggest detection opportunities for defenders

Be concise yet thorough. Format responses with markdown for readability."""

QUICK_STARTERS = [
    "How do I check for persistence mechanisms in Windows?",
    "Walk me through analyzing a suspicious PowerShell command.",
    "What are common signs of lateral movement in a network?",
    "How to detect beaconing activity in network logs?",
    "Explain the steps for triaging a potential ransomware infection.",
    "What registry keys should I check for malware persistence?",
    "How to investigate a suspicious scheduled task on Windows?",
    "What are common LOLBins used by attackers?",
]


@chat_bp.route("/", methods=["GET"])
def chat_page():
    return render_template("chat.html", quick_starters=QUICK_STARTERS)


@chat_bp.route("/send", methods=["POST"])
def send_message():
    """Process a chat message and return the AI response."""
    data = request.get_json()
    message = (data.get("message") or "").strip()
    provider = data.get("provider", "ollama")
    model = data.get("model", "")
    history = data.get("history", [])  # client sends conversation history

    if not message:
        return jsonify({"error": "Empty message."}), 400

    logger.info(f"[Chat] Message from user ({provider}): {message[:80]}...")

    # Build context-aware prompt from history
    if history:
        context_parts = []
        for turn in history[-10:]:  # last 10 turns for context window
            role = turn.get("role", "user")
            content = turn.get("content", "")
            context_parts.append(f"[{role.upper()}]: {content}")
        context = "\n".join(context_parts)
        full_prompt = f"Conversation so far:\n{context}\n\n[USER]: {message}"
    else:
        full_prompt = message

    response = query_ai(
        full_prompt,
        provider=provider,
        model=model or None,
        system=CYBER_SYSTEM_PROMPT,
    )

    return jsonify({"response": response})


@chat_bp.route("/clear", methods=["POST"])
def clear_chat():
    """Clear server-side session (client manages history)."""
    return jsonify({"status": "cleared"})