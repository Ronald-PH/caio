import logging
import random
import time
from datetime import datetime, timedelta

from flask import Blueprint, jsonify, render_template, request

from modules.ai_client import query_ai_full

logger = logging.getLogger(__name__)
honeypot_bp = Blueprint("honeypot_simulator", __name__)

SYSTEM_PROMPT = (
    "You are a red team operator and SOC trainer. Generate realistic attack logs "
    "that mimic real adversary behavior for training and testing purposes."
)

SIMULATOR_PROMPT = """Generate realistic attack logs for a honeypot environment.

Scenario: {scenario}
Attack Type: {attack_type}
Target System: {target_system}
Log Count: {log_count}
Intensity: {intensity} (1=low noise, 5=heavy activity)

Additional customizations:
{customizations}

Generate logs in the following format:
- Use realistic timestamps within the last {time_window} hours
- Include proper source/destination IPs (use realistic ranges)
- Show progression of attack (recon -> exploitation -> persistence -> lateral movement -> exfiltration)
- Mix in some benign traffic to make logs realistic
- For each log line, include severity level (INFO/WARN/ERROR/CRITICAL)

Return ONLY the generated logs, no explanation."""

COMMON_ATTACKS = [
    "SSH brute force", "Web application scanning", "SQL injection", 
    "RDP brute force", "SMB enumeration", "DNS tunneling", 
    "Malicious file download", "Reverse shell", "Privilege escalation",
    "Lateral movement via PsExec", "Data exfiltration", "C2 beaconing"
]

def generate_fake_logs(scenario, attack_type, target_system, log_count, intensity, customizations, time_window_hours=24):
    """Generate fake logs based on parameters."""
    
    # Simple template-based generation if AI is not used for this part
    logs = []
    base_time = datetime.now()
    
    attacker_ips = [f"45.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}" 
                    for _ in range(max(1, intensity))]
    target_ip = target_system if '.' in target_system else f"192.168.1.{random.randint(1,254)}"
    
    phases = ["Scanning", "Recon", "Exploitation", "Persistence", "Lateral Movement", "Exfiltration"]
    
    for i in range(log_count):
        timestamp = base_time - timedelta(seconds=random.randint(0, time_window_hours * 3600))
        attacker = random.choice(attacker_ips)
        phase = phases[min(i // (log_count // len(phases) + 1), len(phases)-1)]
        
        if attack_type == "SSH brute force":
            if i < log_count * 0.7:
                logs.append(f"{timestamp.isoformat()} WARN sshd[{random.randint(1000,9999)}]: Failed password for {random.choice(['root','admin','user'])} from {attacker} port {random.randint(10000,60000)} ssh2")
            else:
                logs.append(f"{timestamp.isoformat()} CRITICAL sshd[{random.randint(1000,9999)}]: Accepted password for root from {attacker} port {random.randint(10000,60000)} ssh2")
        
        elif attack_type == "Web application scanning":
            paths = ["/admin", "/wp-admin", "/phpmyadmin", "/backup", "/.git", "/config", "/api/v1/users"]
            user_agents = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", "sqlmap/1.6", "nmap Scripting Engine", "curl/7.68.0"]
            logs.append(f"{timestamp.isoformat()} INFO {target_ip} - - [{timestamp.strftime('%d/%b/%Y:%H:%M:%S %z')}] \"GET {random.choice(paths)} HTTP/1.1\" {random.choice([200,403,404,500])} {random.randint(200,50000)} \"-\" \"{random.choice(user_agents)}\"")
        
        elif attack_type == "C2 beaconing":
            intervals = [random.randint(5, 60) for _ in range(log_count)]
            logs.append(f"{timestamp.isoformat()} INFO {target_ip} -> {attacker}:443 SYN_ACK [beacon interval: {random.choice(intervals)}s]")
            logs.append(f"{timestamp.isoformat()} INFO {target_ip}:56823 -> {attacker}:443 POST /api/beacon HTTP/1.1 \"User-Agent: Mozilla/5.0\"")
        
        elif attack_type == "Lateral movement":
            internal_ips = [f"192.168.1.{i}" for i in range(10, 50)]
            logs.append(f"{timestamp.isoformat()} CRITICAL WINLOGON[1024]: Logon Type 3 (Network) from {random.choice(internal_ips)} using account DOMAIN\\{random.choice(['svc_deploy','sql_service','backup_user'])}")
            logs.append(f"{timestamp.isoformat()} WARN Service Control Manager: Service {random.choice(['PsExec','WMI','SchTasks'])} started by NT AUTHORITY\\SYSTEM on {target_ip}")
        
        else:  # Generic/mixed
            logs.append(f"{timestamp.isoformat()} {random.choice(['INFO','WARN','ERROR'])} {target_ip} {attacker} {phase}: Activity {i+1}")
    
    return "\n".join(logs)


@honeypot_bp.route("/", methods=["GET"])
def honeypot_page():
    return render_template("honeypot_simulator.html")


@honeypot_bp.route("/generate", methods=["POST"])
def generate_logs():
    """Generate realistic honeypot logs."""
    data = request.get_json()
    scenario = data.get("scenario", "Generic attack simulation")
    attack_type = data.get("attack_type", "SSH brute force")
    target_system = data.get("target_system", "192.168.1.100")
    log_count = min(data.get("log_count", 50), 500)  # Cap at 500 logs
    intensity = min(data.get("intensity", 3), 5)
    customizations = data.get("customizations", "")
    use_ai = data.get("use_ai", False)
    provider = data.get("provider", "ollama")
    model = data.get("model", "")

    logger.info("[HoneypotSim] Generating %d logs for %s", log_count, attack_type)

    if use_ai:
        # Use AI to generate more sophisticated logs
        prompt = SIMULATOR_PROMPT.format(
            scenario=scenario,
            attack_type=attack_type,
            target_system=target_system,
            log_count=log_count,
            intensity=intensity,
            customizations=customizations or "None",
            time_window_hours=24
        )
        result, tokens, cost = query_ai_full(
            prompt, provider=provider, model=model or None, system=SYSTEM_PROMPT
        )
        logs = result
    else:
        logs = generate_fake_logs(scenario, attack_type, target_system, log_count, intensity, customizations)

    return jsonify({
        "logs": logs,
        "metadata": {
            "scenario": scenario,
            "attack_type": attack_type,
            "target_system": target_system,
            "log_count": len(logs.split('\n')),
            "generated_at": datetime.now().isoformat()
        }
    })