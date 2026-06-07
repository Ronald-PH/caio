import logging
import re
import math
from collections import Counter
from flask import Blueprint, jsonify, render_template, request
from modules.ai_client import query_ai_full

logger = logging.getLogger(__name__)
password_bp = Blueprint("password_auditor", __name__)

SYSTEM_PROMPT = (
    "You are a password security expert and compliance auditor. Analyze password "
    "lists for weaknesses, identify patterns, and recommend policy improvements."
)

AUDIT_PROMPT = """Perform a comprehensive password security audit:

=== PASSWORD STATISTICS ===
Total passwords analyzed: {total_count}
Unique passwords: {unique_count}
Average length: {avg_length:.1f}
Minimum length: {min_length}
Maximum length: {max_length}

=== COMMON PATTERNS ===
Most common base words: {common_words}
Most common suffixes/prefixes: {common_patterns}
Character set distribution: {char_distribution}

=== ENTROPY ANALYSIS ===
Low entropy (< 40 bits): {low_entropy} passwords
Medium entropy (40-60 bits): {medium_entropy}
High entropy (> 60 bits): {high_entropy}

=== DICTIONARY MATCHES ===
Found in breach dictionaries: {breach_matches}
Common keyboard patterns: {keyboard_patterns}
Seasonal/date patterns: {date_patterns}

=== SAMPLE WEAK PASSWORDS ===
{sample_weak}

Provide:

1. **Overall Security Score**: 0-100 with rating (F through A)
2. **Entropy Distribution**: Chart-ready breakdown
3. **Top Violations**: Most common policy failures
4. **Pattern Analysis**: What users are doing wrong (incrementing numbers, seasons, etc.)
5. **Compliance Gaps**: NIST/PCI/HIPAA password requirement mapping
6. **Policy Recommendations**: Specific, actionable changes
7. **User Education Points**: What to tell employees"""


def calculate_entropy(password: str) -> float:
    """Calculate total Shannon entropy (bits) of a password."""
    if not password:
        return 0.0

    freq = Counter(password)
    length = len(password)
    total_entropy = 0.0

    for count in freq.values():
        p = count / length
        total_entropy -= count * math.log2(p)

    return total_entropy


def analyze_password_patterns(passwords: list) -> dict:
    """Identify common patterns in passwords."""
    results = {
        "common_words": [],
        "common_patterns": [],
        "keyboard_patterns": [],
        "date_patterns": [],
        "char_distribution": {"lower": 0, "upper": 0, "digits": 0, "special": 0}
    }

    # Common base words and patterns
    word_counter = Counter()
    pattern_counter = Counter()

    # Keyboard walk patterns
    keyboard_rows = [
        "qwertyuiop", "asdfghjkl", "zxcvbnm",
        "qwerty", "wertyu", "ertyui", "rtyuio", "tyuiop",
        "asdfgh", "sdfghj", "dfghjk", "fghjkl"
    ]

    # Date patterns
    date_pattern = re.compile(r'(19|20)\d{2}|(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)', re.I)

    for pwd in passwords:
        lower_pwd = pwd.lower()

        # Character distribution
        if re.search(r'[a-z]', pwd):
            results["char_distribution"]["lower"] += 1
        if re.search(r'[A-Z]', pwd):
            results["char_distribution"]["upper"] += 1
        if re.search(r'\d', pwd):
            results["char_distribution"]["digits"] += 1
        if re.search(r'[^a-zA-Z0-9]', pwd):
            results["char_distribution"]["special"] += 1

        # Check for keyboard patterns
        for kb in keyboard_rows:
            if kb in lower_pwd or kb[::-1] in lower_pwd:
                results["keyboard_patterns"].append(pwd)
                pattern_counter["keyboard_walk"] += 1
                break

        # Check for dates
        if date_pattern.search(pwd):
            results["date_patterns"].append(pwd)
            pattern_counter["contains_date"] += 1

        # Extract base words (remove trailing numbers/symbols)
        base_word = re.sub(r'[\d!@#$%^&*()_+]+$', '', pwd)
        if len(base_word) >= 4:
            word_counter[base_word.lower()] += 1

    results["common_words"] = word_counter.most_common(10)
    results["common_patterns"] = pattern_counter.most_common(5)

    return results


@password_bp.route("/", methods=["GET"])
def password_page():
    return render_template("password_auditor.html")


@password_bp.route("/audit", methods=["POST"])
def audit_passwords():
    # Parse JSON with silent=True to avoid throwing on malformed input
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid or missing JSON payload. Please set Content-Type: application/json"}), 400

    passwords_text = (data.get("passwords") or "").strip()
    is_hashed = data.get("is_hashed", False)
    provider = data.get("provider", "ollama")
    model = data.get("model", "")

    if not passwords_text:
        return jsonify({"error": "No passwords provided."}), 400

    # Parse passwords (one per line)
    raw_passwords = [p.strip() for p in passwords_text.split('\n') if p.strip()]

    # If hashed, we can't analyze patterns but can warn
    if is_hashed:
        return jsonify({
            "analysis": "⚠️ Passwords appear to be hashed. Password auditors need plaintext or decoded passwords to analyze patterns, entropy, and dictionary weaknesses. Please provide plaintext passwords for meaningful analysis.",
            "warning": "Hashed passwords detected - limited analysis available",
            "tokens_used": 0,
            "cost_estimate": 0
        })

    # Analyze passwords (limit to 1000 for performance)
    passwords = raw_passwords[:1000]

    # Calculate statistics
    lengths = [len(p) for p in passwords]
    entropies = [calculate_entropy(p) for p in passwords]

    low_entropy = sum(1 for e in entropies if e < 40)
    medium_entropy = sum(1 for e in entropies if 40 <= e < 60)
    high_entropy = sum(1 for e in entropies if e >= 60)

    patterns = analyze_password_patterns(passwords)

    # Get sample weak passwords (low entropy)
    weak_samples = [passwords[i] for i, e in enumerate(entropies) if e < 40][:10]

    logger.info(f"[PasswordAuditor] Analyzing {len(passwords)} passwords")

    prompt = AUDIT_PROMPT.format(
        total_count=len(passwords),
        unique_count=len(set(passwords)),
        avg_length=sum(lengths) / len(lengths) if lengths else 0,
        min_length=min(lengths) if lengths else 0,
        max_length=max(lengths) if lengths else 0,
        common_words=", ".join([f"{w[0]}({w[1]})" for w in patterns["common_words"][:5]]),
        common_patterns=", ".join([f"{p[0]}({p[1]})" for p in patterns["common_patterns"][:3]]),
        char_distribution=str(patterns["char_distribution"]),
        low_entropy=low_entropy,
        medium_entropy=medium_entropy,
        high_entropy=high_entropy,
        breach_matches="Not checked - would require HaveIBeenPwned API",
        keyboard_patterns=len(patterns["keyboard_patterns"]),
        date_patterns=len(patterns["date_patterns"]),
        sample_weak="\n".join(weak_samples[:5]) if weak_samples else "None found"
    )

    try:
        result, tokens, cost = query_ai_full(
            prompt, provider=provider, model=model or None, system=SYSTEM_PROMPT
        )
    except Exception as e:
        logger.exception("AI query failed")
        return jsonify({"error": f"AI analysis failed: {str(e)}"}), 500

    # Persist to database
    try:
        from database import save_scan
        save_scan(
            target=f"{len(passwords)} passwords",
            module_type="password_auditor",
            ai_provider=provider,
            result_text=result,
            tokens_used=tokens,
            cost_estimate=cost,
        )
    except Exception as db_exc:
        logger.warning("DB save failed: %s", db_exc)

    return jsonify({
        "analysis": result,
        "statistics": {
            "total": len(passwords),
            "unique": len(set(passwords)),
            "avg_length": round(sum(lengths) / len(lengths), 1) if lengths else 0,
            "entropy_distribution": {
                "low": low_entropy,
                "medium": medium_entropy,
                "high": high_entropy
            }
        },
        "weak_samples": weak_samples[:10],
        "tokens_used": tokens,
        "cost_estimate": cost,
    })