import logging
import threading
import time
import smtplib
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from flask import Blueprint, jsonify, render_template, request

logger = logging.getLogger(__name__)
scheduler_bp = Blueprint("scheduler", __name__)

# In-memory schedule store (use database for persistence in production)
scheduled_jobs = {}
job_lock = threading.Lock()

SCHEDULE_DB_PATH = "schedules.json"


def load_schedules():
    """Load schedules from disk."""
    global scheduled_jobs
    try:
        with open(SCHEDULE_DB_PATH, 'r') as f:
            scheduled_jobs = json.load(f)
    except FileNotFoundError:
        scheduled_jobs = {}


def save_schedules():
    """Save schedules to disk."""
    with open(SCHEDULE_DB_PATH, 'w') as f:
        json.dump(scheduled_jobs, f, indent=2)


def parse_cron(cron_string: str) -> dict:
    """Parse cron expression into components."""
    # Simple parser for minute hour day month day_of_week
    parts = cron_string.split()
    if len(parts) != 5:
        return None
    
    return {
        "minute": parts[0],
        "hour": parts[1],
        "day": parts[2],
        "month": parts[3],
        "day_of_week": parts[4]
    }


def should_run(job: dict, last_run: datetime) -> bool:
    """Check if scheduled job should run now."""
    if not job.get("enabled", True):
        return False
    
    schedule = job.get("schedule", {})
    
    now = datetime.now()
    
    # Check if enough time has passed since last run
    if last_run:
        min_interval = job.get("min_interval_minutes", 60)
        if (now - last_run).total_seconds() < min_interval * 60:
            return False
    
    # Check minute
    if schedule.get("minute") != "*":
        if now.minute != int(schedule["minute"]):
            return False
    
    # Check hour
    if schedule.get("hour") != "*":
        if now.hour != int(schedule["hour"]):
            return False
    
    # Check day of month
    if schedule.get("day") != "*":
        if now.day != int(schedule["day"]):
            return False
    
    # Check day of week (0=Monday or 0=Sunday depending on system)
    if schedule.get("day_of_week") != "*":
        dow = now.weekday()  # 0=Monday
        if dow != int(schedule["day_of_week"]) - 1:
            return False
    
    return True


def send_email_digest(recipient: str, subject: str, body: str):
    """Send email digest using configured SMTP."""
    smtp_server = os.environ.get("SMTP_SERVER", "")
    smtp_port = int(os.environ.get("SMTP_PORT", 587))
    smtp_user = os.environ.get("SMTP_USER", "")
    smtp_pass = os.environ.get("SMTP_PASSWORD", "")
    
    if not smtp_server:
        logger.warning("SMTP not configured - skipping email digest")
        return
    
    try:
        msg = MIMEMultipart()
        msg["From"] = smtp_user
        msg["To"] = recipient
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))
        
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)
        
        logger.info(f"Email digest sent to {recipient}")
    except Exception as e:
        logger.error(f"Failed to send email: {e}")


def scheduler_worker():
    """Background worker that runs scheduled jobs."""
    last_run_tracker = {}
    
    while True:
        try:
            now = datetime.now()
            
            for job_id, job in scheduled_jobs.items():
                last_run = last_run_tracker.get(job_id)
                
                if should_run(job, last_run):
                    logger.info(f"Running scheduled job: {job_id}")
                    
                    # Execute the scan
                    try:
                        from modules.jobs import get_manager
                        from modules.recon import _run_recon_job
                        from modules.vuln_scan import run_url_scan
                        
                        module_name = job.get("module", "recon")
                        targets = job.get("targets", [])
                        
                        results = []
                        for target in targets:
                            job_id_new = get_manager().submit(
                                _run_recon_job if module_name == "recon" else None,
                                target,
                                job.get("provider", "ollama"),
                                job.get("model", "")
                            )
                            results.append({"target": target, "job_id": job_id_new})
                        
                        last_run_tracker[job_id] = now
                        
                        # Send digest if configured
                        if job.get("email_recipient"):
                            digest_body = f"Scheduled scan completed at {now}\n\n"
                            for r in results:
                                digest_body += f"Target: {r['target']}\nJob ID: {r['job_id']}\n\n"
                            send_email_digest(job["email_recipient"], f"CAIO Scan: {job_id}", digest_body)
                    
                    except Exception as e:
                        logger.error(f"Scheduled job failed: {e}")
            
        except Exception as e:
            logger.error(f"Scheduler worker error: {e}")
        
        time.sleep(60)  # Check every minute


# Start scheduler thread
scheduler_thread = threading.Thread(target=scheduler_worker, daemon=True)
scheduler_thread.start()


@scheduler_bp.route("/", methods=["GET"])
def scheduler_page():
    return render_template("scheduler.html")


@scheduler_bp.route("/jobs", methods=["GET"])
def list_jobs():
    """List all scheduled jobs."""
    return jsonify({"jobs": scheduled_jobs})


@scheduler_bp.route("/jobs", methods=["POST"])
def create_job():
    """Create a new scheduled job."""
    data = request.get_json()
    
    job_id = data.get("job_id", f"job_{int(time.time())}")
    scheduled_jobs[job_id] = {
        "job_id": job_id,
        "name": data.get("name", ""),
        "module": data.get("module", "recon"),
        "targets": data.get("targets", []),
        "schedule": parse_cron(data.get("cron", "0 9 * * *")),
        "provider": data.get("provider", "ollama"),
        "model": data.get("model", ""),
        "email_recipient": data.get("email_recipient", ""),
        "enabled": data.get("enabled", True),
        "created_at": datetime.now().isoformat()
    }
    
    save_schedules()
    return jsonify({"status": "created", "job_id": job_id})


@scheduler_bp.route("/jobs/<job_id>", methods=["DELETE"])
def delete_job(job_id):
    """Delete a scheduled job."""
    if job_id in scheduled_jobs:
        del scheduled_jobs[job_id]
        save_schedules()
        return jsonify({"status": "deleted"})
    return jsonify({"error": "Job not found"}), 404


@scheduler_bp.route("/jobs/<job_id>/toggle", methods=["POST"])
def toggle_job(job_id):
    """Enable/disable a scheduled job."""
    if job_id in scheduled_jobs:
        scheduled_jobs[job_id]["enabled"] = not scheduled_jobs[job_id].get("enabled", True)
        save_schedules()
        return jsonify({"status": "toggled", "enabled": scheduled_jobs[job_id]["enabled"]})
    return jsonify({"error": "Job not found"}), 404


# Load schedules on startup
load_schedules()