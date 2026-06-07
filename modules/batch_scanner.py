import logging
import csv
import io
import json
import uuid
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from flask import Blueprint, jsonify, render_template, request, send_file
from modules.ai_client import query_ai_full
from database import save_scan   # <-- ADDED

logger = logging.getLogger(__name__)
batch_bp = Blueprint("batch_scanner", __name__)

# In-memory batch storage (use database in production)
batch_results = {}
batch_lock = threading.Lock()


def run_single_target(target: str, module: str, provider: str, model: str, context: dict = None) -> dict:
    """Run a single module against a target and save result to database."""
    result = {
        "target": target,
        "module": module,
        "provider": provider,
        "status": "pending",
        "analysis": "",
        "error": None,
        "timestamp": datetime.now().isoformat()
    }

    try:
        if module == "recon":
            from modules.recon import dns_lookup, subdomain_scan, port_scan, whois_lookup

            dns = dns_lookup(target)
            subs = subdomain_scan(target)
            ports = port_scan(target)
            whois = whois_lookup(target)

            # Build summary for AI (same format as recon.py)
            subdomain_lines = "\n".join(subs) if subs else "None found"
            port_lines = (
                "\n".join(f"  Port {p['port']}: OPEN  {p['banner']}" for p in ports)
                if ports else "No common ports open"
            )
            recon_summary = (
                f"TARGET: {target}\n\n"
                f"=== DNS Records ===\n"
                f"A Records: {dns['A']}\nMX Records: {dns['MX']}\nTXT Records: {dns['TXT']}\n"
                f"DNS Errors: {dns['errors']}\n\n"
                f"=== Discovered Subdomains ===\n{subdomain_lines}\n\n"
                f"=== Open Ports ===\n{port_lines}\n\n"
                f"=== WHOIS Data ===\n{whois[:2000]}"
            )

            prompt = (
                f"Analyze this reconnaissance data for the target '{target}'.\n\n"
                f"{recon_summary}\n\n"
                "Please:\n"
                "1. Highlight risky open ports and their typical services.\n"
                "2. Flag any interesting or suspicious subdomains.\n"
                "3. Note potential misconfigurations from DNS/WHOIS data.\n"
                "4. Summarize the overall attack surface and risk level.\n"
                "5. Provide specific, actionable recommendations."
            )
            system = (
                "You are a senior penetration tester and threat intelligence analyst. "
                "Provide detailed, professional analysis with specific risk ratings."
            )

            ai_result, tokens, cost = query_ai_full(prompt, provider=provider, model=model or None, system=system)

            result["analysis"] = {
                "dns": dns,
                "subdomains": subs,
                "ports": ports,
                "whois": whois[:3000],
                "ai_analysis": ai_result
            }
            result["status"] = "completed"

            # Save to database
            save_scan(
                target=target,
                module_type="recon",
                ai_provider=provider,
                result_text=ai_result,
                tokens_used=tokens,
                cost_estimate=cost,
            )

        elif module == "vuln_scan":
            from modules.vuln_scan import probe_url

            probe = probe_url(target)
            prompt = f"Analyze security of {target}. Probe results: {probe}"
            ai_result, tokens, cost = query_ai_full(prompt, provider=provider, model=model or None)

            result["analysis"] = {
                "probe": probe,
                "ai_analysis": ai_result
            }
            result["status"] = "completed"

            # Save to database
            save_scan(
                target=target,
                module_type="vuln_scan",
                ai_provider=provider,
                result_text=ai_result,
                tokens_used=tokens,
                cost_estimate=cost,
            )

        elif module == "log_analysis":
            # For batch mode, logs would be provided in context
            logs = context.get("logs", "") if context else ""
            if logs:
                prompt = f"Analyze these logs for security issues:\n{logs[:5000]}"
                ai_result, tokens, cost = query_ai_full(prompt, provider=provider, model=model or None)
                result["analysis"] = {"ai_analysis": ai_result}
                result["status"] = "completed"

                save_scan(
                    target=target,
                    module_type="log_analysis",
                    ai_provider=provider,
                    result_text=ai_result,
                    tokens_used=tokens,
                    cost_estimate=cost,
                )
            else:
                result["status"] = "error"
                result["error"] = "No logs provided for analysis"

        else:
            result["status"] = "error"
            result["error"] = f"Module {module} not supported in batch mode yet"

    except Exception as e:
        logger.error(f"Batch scan failed for {target}: {e}")
        result["status"] = "error"
        result["error"] = str(e)

    return result


@batch_bp.route("/", methods=["GET"])
def batch_page():
    return render_template("batch_scanner.html")


@batch_bp.route("/run", methods=["POST"])
def run_batch():
    """Run batch scan from uploaded CSV or pasted list."""
    data = request.get_json()
    targets_text = (data.get("targets") or "").strip()
    module = data.get("module", "recon")
    provider = data.get("provider", "ollama")
    model = data.get("model", "")
    max_workers = min(data.get("max_workers", 5), 10)

    if not targets_text:
        return jsonify({"error": "No targets provided."}), 400

    # Parse targets (one per line or CSV)
    targets = [t.strip() for t in targets_text.split('\n') if t.strip()]

    if not targets:
        return jsonify({"error": "No valid targets found."}), 400

    logger.info(f"[BatchScanner] Running {module} on {len(targets)} targets with {max_workers} workers")

    batch_id = str(uuid.uuid4())[:8]
    batch_results[batch_id] = {
        "id": batch_id,
        "module": module,
        "provider": provider,
        "targets": targets,
        "results": [],
        "status": "running",
        "started_at": datetime.now().isoformat(),
        "completed_at": None
    }

    def run_batch_async():
        results = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(run_single_target, t, module, provider, model): t for t in targets}

            for future in as_completed(futures):
                result = future.result()
                results.append(result)

        batch_results[batch_id]["results"] = results
        batch_results[batch_id]["status"] = "completed"
        batch_results[batch_id]["completed_at"] = datetime.now().isoformat()
        logger.info(f"[BatchScanner] Completed {len(results)} scans")

    # Run async
    thread = threading.Thread(target=run_batch_async)
    thread.start()

    return jsonify({"batch_id": batch_id, "total_targets": len(targets)})


@batch_bp.route("/status/<batch_id>", methods=["GET"])
def batch_status(batch_id):
    """Get batch scan status."""
    batch = batch_results.get(batch_id)
    if not batch:
        return jsonify({"error": "Batch not found"}), 404

    completed = sum(1 for r in batch["results"] if r["status"] == "completed")
    errors = sum(1 for r in batch["results"] if r["status"] == "error")

    return jsonify({
        "status": batch["status"],
        "total": len(batch["targets"]),
        "completed": completed,
        "errors": errors,
        "results": batch["results"] if batch["status"] == "completed" else [],
        "started_at": batch["started_at"],
        "completed_at": batch["completed_at"]
    })


@batch_bp.route("/export/<batch_id>", methods=["GET"])
def export_batch(batch_id):
    """Export batch results as CSV."""
    batch = batch_results.get(batch_id)
    if not batch:
        return jsonify({"error": "Batch not found"}), 404

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Target", "Module", "Status", "Error", "Analysis Summary", "Timestamp"])

    for result in batch["results"]:
        writer.writerow([
            result["target"],
            result["module"],
            result["status"],
            result.get("error", ""),
            json.dumps(result.get("analysis", {}))[:500],
            result.get("timestamp", "")
        ])

    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype="text/csv",
        as_attachment=True,
        download_name=f"batch_scan_{batch_id}.csv"
    )