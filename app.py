"""
Cybersecurity AI Orchestrator (CAIO)
=====================================
A unified web dashboard for AI-assisted cybersecurity tasks.
Runs on Windows 11 with local Ollama models and/or commercial LLMs.
"""

import logging
import os
import threading
from flask import Flask, jsonify, render_template, request, send_file, abort
from dotenv import load_dotenv
from modules.threat_profiler import threat_bp
from modules.payload_dna import payload_bp
from modules.network_storyteller import story_bp
from modules.cve_feed import cve_bp
from modules.honeypot_simulator import honeypot_bp
from modules.redteam_playbook import playbook_bp

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler("app.log", encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)


def create_app():
    """Application factory."""
    app = Flask(__name__)
    app.secret_key = os.environ.get("SECRET_KEY", "caio-dev-secret-change-me")

    # ── Initialise database ──────────────────────────────────────────────
    from database import init_db
    with app.app_context():
        init_db()

    # ── Register blueprints ──────────────────────────────────────────────
    from modules.recon import recon_bp
    from modules.log_analysis import log_bp
    from modules.vuln_scan import vuln_bp
    from modules.chat import chat_bp
    from modules.settings import settings_bp
    from modules.dashboard import dashboard_bp
    from modules.osint_profiler import osint_bp
    from modules.email_forensics import email_bp
    from modules.password_auditor import password_bp
    from modules.siem_rule_generator import siem_bp
    from modules.supply_chain_risk import supply_bp
    from modules.batch_scanner import batch_bp
    from modules.compliance_report import compliance_bp

    app.register_blueprint(dashboard_bp)
    app.register_blueprint(recon_bp, url_prefix="/recon")
    app.register_blueprint(log_bp, url_prefix="/log-analysis")
    app.register_blueprint(vuln_bp, url_prefix="/vuln-scan")
    app.register_blueprint(chat_bp, url_prefix="/chat")
    app.register_blueprint(settings_bp, url_prefix="/settings")
    app.register_blueprint(threat_bp, url_prefix="/threat-profiler")
    app.register_blueprint(payload_bp, url_prefix="/payload-dna")
    app.register_blueprint(story_bp, url_prefix="/network-storyteller")
    app.register_blueprint(cve_bp, url_prefix="/cve-feed")
    app.register_blueprint(honeypot_bp, url_prefix="/honeypot-simulator")
    app.register_blueprint(playbook_bp, url_prefix="/redteam-playbook")
    app.register_blueprint(osint_bp, url_prefix="/osint-profiler")
    app.register_blueprint(email_bp, url_prefix="/email-forensics")
    app.register_blueprint(password_bp, url_prefix="/password-auditor")
    app.register_blueprint(siem_bp, url_prefix="/siem-rules")
    app.register_blueprint(supply_bp, url_prefix="/supply-chain")
    app.register_blueprint(batch_bp, url_prefix="/batch")
    app.register_blueprint(compliance_bp, url_prefix="/compliance")
    
    # ── /progress/<job_id> ───────────────────────────────────────────────
    @app.route("/progress/<job_id>")
    def job_progress(job_id):
        """Poll background job status. Returns JSON."""
        from modules.jobs import get_manager
        return jsonify(get_manager().status(job_id))

    # ── /history ─────────────────────────────────────────────────────────
    @app.route("/history")
    def history():
        from database import list_scans
        module_filter   = request.args.get("module", "")
        provider_filter = request.args.get("provider", "")
        target_filter   = request.args.get("target", "")
        days_filter     = request.args.get("days", type=int)

        scans = list_scans(
            module_type=module_filter or None,
            ai_provider=provider_filter or None,
            target=target_filter or None,
            days=days_filter,
        )
        return render_template(
            "history.html",
            scans=scans,
            filters={
                "module": module_filter,
                "provider": provider_filter,
                "target": target_filter,
                "days": days_filter or "",
            },
        )

    @app.route("/history/<int:scan_id>")
    def history_detail(scan_id):
        from database import get_scan
        scan = get_scan(scan_id)
        if not scan:
            abort(404)
        return jsonify(scan)

    @app.route("/history/<int:scan_id>/delete", methods=["POST"])
    def history_delete(scan_id):
        from database import delete_scan
        delete_scan(scan_id)
        return jsonify({"status": "deleted"})

    # ── /cost-dashboard ───────────────────────────────────────────────────
    @app.route("/cost-dashboard")
    def cost_dashboard():
        from database import get_cost_stats
        stats = get_cost_stats()
        return render_template("cost_dashboard.html", stats=stats)

    @app.route("/cost-dashboard/api")
    def cost_dashboard_api():
        from database import get_cost_stats
        return jsonify(get_cost_stats())
    @app.route("/debug/port/<host>/<int:port>")
    def debug_port(host, port):
        """Debug a single port."""
        from modules.recon import _check_port
        result = _check_port(host, port, timeout=2)
        if result:
            return jsonify({"open": True, "port": port, "details": result})
        return jsonify({"open": False, "port": port})
    # ── /health ───────────────────────────────────────────────────────────
    @app.route("/health")
    def health():
        """Check connectivity to each configured AI provider."""
        import requests as req

        result = {}

        # Ollama - with proper error handling and URL validation
        endpoint = os.environ.get("OLLAMA_ENDPOINT", "").strip()
        if not endpoint:
            endpoint = "http://localhost:11434"
        
        # Ensure the endpoint has a scheme
        if not endpoint.startswith(("http://", "https://")):
            endpoint = "http://" + endpoint
        
        # Remove trailing slash if present
        endpoint = endpoint.rstrip('/')
        
        try:
            url = f"{endpoint}/api/tags"
            print(f"[Health] Testing Ollama at: {url}")  # Debug output
            r = req.get(url, timeout=3)
            if r.status_code == 200:
                models = [m["name"] for m in r.json().get("models", [])]
                result["ollama"] = {"status": "ok", "models": models, "endpoint": endpoint}
            else:
                result["ollama"] = {"status": "error", "message": f"HTTP {r.status_code}"}
        except Exception as exc:
            result["ollama"] = {"status": "error", "message": str(exc), "endpoint": endpoint}

        # OpenAI
        if os.environ.get("OPENAI_API_KEY"):
            try:
                import openai
                client = openai.OpenAI(api_key=os.environ["OPENAI_API_KEY"])
                client.models.list()
                result["openai"] = {"status": "ok"}
            except Exception as exc:
                result["openai"] = {"status": "error", "message": str(exc)}
        else:
            result["openai"] = {"status": "not_configured"}

        # Anthropic
        if os.environ.get("ANTHROPIC_API_KEY"):
            try:
                import anthropic
                c = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
                c.models.list()
                result["claude"] = {"status": "ok"}
            except Exception as exc:
                result["claude"] = {"status": "error", "message": str(exc)}
        else:
            result["claude"] = {"status": "not_configured"}

        overall = "ok" if all(v.get("status") in ("ok", "not_configured") for v in result.values()) else "degraded"
        return jsonify({"overall": overall, "providers": result})

    # ── /export/pdf/<scan_id> ─────────────────────────────────────────────
    @app.route("/export/pdf/<int:scan_id>")
    def export_pdf(scan_id):
        """Export a past scan result as PDF."""
        from database import get_scan
        import tempfile, pathlib, io

        scan = get_scan(scan_id)
        if not scan:
            abort(404)

        # Build HTML for the PDF
        html_content = render_template("pdf_export.html", scan=scan)

        # Try weasyprint first, fall back to pdfkit, then plain HTML download
        try:
            from weasyprint import HTML as WH
            pdf_bytes = WH(string=html_content).write_pdf()
            return send_file(
                io.BytesIO(pdf_bytes),
                mimetype="application/pdf",
                as_attachment=True,
                download_name=f"caio-scan-{scan_id}.pdf",
            )
        except ImportError:
            pass

        try:
            import pdfkit
            pdf_bytes = pdfkit.from_string(html_content, False)
            return send_file(
                io.BytesIO(pdf_bytes),
                mimetype="application/pdf",
                as_attachment=True,
                download_name=f"caio-scan-{scan_id}.pdf",
            )
        except Exception:
            pass

        # Final fallback: return the HTML with print-friendly styling
        return html_content, 200, {"Content-Type": "text/html; charset=utf-8"}

    logger.info("CAIO application initialised successfully.")
    return app


app = create_app()

if __name__ == "__main__":
    logger.info("Starting CAIO on http://127.0.0.1:5000")
    app.run(debug=True, host="127.0.0.1", port=5000, threaded=True)
