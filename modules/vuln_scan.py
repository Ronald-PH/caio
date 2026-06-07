import logging
import os
import urllib.parse

from flask import Blueprint, jsonify, render_template, request

from modules.ai_client import query_ai_full

logger = logging.getLogger(__name__)
vuln_bp = Blueprint("vuln_scan", __name__)

SYSTEM_PROMPT = (
    "You are a senior application security engineer and penetration tester. "
    "Identify vulnerabilities with precision, assign CVSS-style severity ratings, "
    "and provide actionable remediation steps."
)

VULN_PROMPT_URL = """Perform a security assessment for the following URL/web target:

URL: {url}
HTTP Headers / Server Response:
{headers}

Additional Context:
{context}

Analyze for:
1. **Web Application Vulnerabilities**: SQLi, XSS, CSRF, IDOR, SSRF, XXE, RCE possibilities.
2. **Security Headers**: Missing CSP, HSTS, X-Frame-Options, etc.
3. **Information Disclosure**: Server version, error messages, directory listing.
4. **Authentication Issues**: Weak auth, missing rate-limiting indicators.
5. **TLS/SSL**: Certificate issues, weak ciphers (infer from headers if possible).
6. **Risk Rating**: Overall risk (Critical/High/Medium/Low) with justification.
7. **Remediation**: Specific fixes for each finding.

Format with clear severity labels for each finding."""

VULN_PROMPT_FILE = """Perform a security code/config review for the following {file_type}:

Filename: {filename}
Content:
---
{content}
---

Analyze for:
1. **Hardcoded Secrets**: API keys, passwords, tokens, private keys.
2. **Vulnerable Dependencies**: Outdated packages with known CVEs.
3. **Misconfigurations**: Insecure defaults, excessive permissions, exposed ports.
4. **Injection Vulnerabilities**: Command injection, path traversal, template injection.
5. **Insecure Coding Patterns**: eval(), exec(), unsafe deserialization, weak crypto.
6. **Secrets Management**: Env var usage, secret scanning patterns.
7. **Risk Rating**: Overall risk (Critical/High/Medium/Low).
8. **Line-by-Line Findings**: Reference specific line numbers when possible.
9. **Remediation**: Concrete fixes for each issue.

Format with severity labels (🔴 Critical / 🟠 High / 🟡 Medium / 🟢 Low / ℹ️ Info)."""


def probe_url(url: str) -> dict:
    result = {"headers": {}, "status": None, "error": None}
    try:
        import urllib.request
        parsed = urllib.parse.urlparse(url)
        if not parsed.scheme:
            url = "http://" + url
        req = urllib.request.Request(url, method="HEAD")
        req.add_header("User-Agent", "CAIO-SecurityScanner/1.0")
        with urllib.request.urlopen(req, timeout=5) as resp:
            result["status"] = resp.status
            result["headers"] = dict(resp.headers)
    except Exception as exc:
        result["error"] = str(exc)
    return result


def detect_file_type(filename: str) -> str:
    ext = os.path.splitext(filename.lower())[1]
    mapping = {
        ".py": "Python source code", ".js": "JavaScript source code",
        ".ts": "TypeScript source code", ".php": "PHP source code",
        ".java": "Java source code", ".go": "Go source code",
        ".rb": "Ruby source code", ".dockerfile": "Dockerfile",
        ".tf": "Terraform configuration", ".yaml": "YAML configuration",
        ".yml": "YAML configuration", ".json": "JSON configuration",
        ".env": "Environment file", ".sh": "Shell script",
        ".bat": "Windows batch script", ".ps1": "PowerShell script",
        ".xml": "XML configuration", ".conf": "Configuration file",
        ".cfg": "Configuration file", ".ini": "INI configuration",
        ".txt": "text file",
    }
    if filename.lower() == "dockerfile":
        return "Dockerfile"
    if filename.lower() in ("requirements.txt", "package.json", "go.mod", "pom.xml", "gemfile"):
        return "dependency manifest"
    return mapping.get(ext, "source/config file")


@vuln_bp.route("/", methods=["GET"])
def vuln_page():
    return render_template("vuln_scan.html")


@vuln_bp.route("/scan", methods=["POST"])
def run_scan():
    """Run AI-assisted vulnerability assessment and persist result."""
    provider = request.form.get("provider", "ollama")
    model = request.form.get("model", "")
    scan_type = request.form.get("scan_type", "url")

    if scan_type == "url":
        url = (request.form.get("url") or "").strip()
        if not url:
            return jsonify({"error": "No URL provided."}), 400

        logger.info("[VulnScan] URL scan: %s", url)
        probe = probe_url(url)
        headers_text = "\n".join(f"{k}: {v}" for k, v in probe.get("headers", {}).items())
        if probe.get("error"):
            headers_text = f"Could not retrieve headers: {probe['error']}"

        context = f"HTTP Status: {probe.get('status', 'N/A')}"
        prompt = VULN_PROMPT_URL.format(
            url=url, headers=headers_text or "No headers retrieved.", context=context
        )
        result, tokens, cost = query_ai_full(
            prompt, provider=provider, model=model or None, system=SYSTEM_PROMPT
        )

        try:
            from database import save_scan
            save_scan(
                target=url, module_type="vuln_scan", ai_provider=provider,
                result_text=result, tokens_used=tokens, cost_estimate=cost,
            )
        except Exception as db_exc:
            logger.warning("DB save failed: %s", db_exc)

        return jsonify({
            "analysis": result, "probe": probe,
            "tokens_used": tokens, "cost_estimate": cost,
        })

    else:  # file upload
        if "file" not in request.files:
            return jsonify({"error": "No file uploaded."}), 400

        f = request.files["file"]
        filename = f.filename or "unknown"
        try:
            content = f.read().decode("utf-8", errors="replace")
        except Exception as exc:
            return jsonify({"error": f"Cannot read file: {exc}"}), 400

        if len(content) > 30_000:
            content = content[:30_000] + "\n\n[... truncated ...]"

        file_type = detect_file_type(filename)
        logger.info("[VulnScan] File scan: %s (%s)", filename, file_type)
        prompt = VULN_PROMPT_FILE.format(file_type=file_type, filename=filename, content=content)
        result, tokens, cost = query_ai_full(
            prompt, provider=provider, model=model or None, system=SYSTEM_PROMPT
        )

        try:
            from database import save_scan
            save_scan(
                target=filename, module_type="vuln_scan", ai_provider=provider,
                result_text=result, tokens_used=tokens, cost_estimate=cost,
            )
        except Exception as db_exc:
            logger.warning("DB save failed: %s", db_exc)

        return jsonify({
            "analysis": result, "filename": filename, "file_type": file_type,
            "tokens_used": tokens, "cost_estimate": cost,
        })
