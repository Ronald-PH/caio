import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from flask import Blueprint, jsonify, render_template, request

from modules.ai_client import query_ai_full
from modules.jobs import get_manager

logger = logging.getLogger(__name__)
recon_bp = Blueprint("recon", __name__)

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail",
    "admin", "portal", "api", "dev", "staging", "test", "uat",
    "vpn", "remote", "rdp", "ssh", "sftp", "git", "gitlab",
    "jenkins", "jira", "confluence", "wiki", "docs", "support",
    "help", "status", "cdn", "static", "assets", "media",
    "shop", "store", "checkout", "payment", "secure", "auth",
    "login", "sso", "identity", "ns1", "ns2", "mx", "smtp2",
    "backup", "old", "legacy", "beta", "mobile", "m", "app",
]

COMMON_PORTS = [
    # Web
    80, 443, 8080, 8443, 8000, 8008, 8888, 8333,
    # SSH & Remote Access
    22, 23, 3389, 5900, 5901, 5800, 2222, 22222,
    # Databases
    3306, 5432, 1433, 1521, 27017, 6379, 9200, 9300,
    # Mail
    25, 465, 587, 110, 995, 143, 993,
    # File Transfer
    21, 20, 69, 989, 990, 2049, 445, 139,
    # Windows Services
    135, 137, 138, 139, 445, 3389, 5985, 5986,
    # DNS & Network
    53, 67, 68, 123, 161, 162, 389, 636, 3268, 3269,
    # Proxy & Cache
    3128, 8080, 8118, 1080, 9050,
    # DevOps & Containers
    2375, 2376, 2377, 7946, 4789, 9092, 2181,
    # Other services
    1080, 4443, 10000, 5000, 3000, 4200, 9000, 9001
]


# ── DNS ───────────────────────────────────────────────────────────────────────

def dns_lookup(target: str) -> dict:
    import dns.resolver
    import dns.exception

    results = {"A": [], "MX": [], "TXT": [], "errors": []}

    # A records via socket (already reliable)
    try:
        addrs = socket.getaddrinfo(target, None, socket.AF_INET)
        results["A"] = list({a[4][0] for a in addrs})
    except Exception as exc:
        results["errors"].append(f"A record error: {exc}")

    # MX and TXT using dnspython – treat "no answer" as empty, not error
    for rtype in ("MX", "TXT"):
        try:
            answers = dns.resolver.resolve(target, rtype)
            results[rtype] = [str(r) for r in answers]
        except dns.resolver.NoAnswer:
            # No record of this type – that's fine, keep empty list
            continue
        except dns.resolver.NXDOMAIN:
            # Domain doesn't exist – critical error
            results["errors"].append(f"{rtype} error: domain does not exist")
            continue
        except Exception as exc:
            # Any other DNS error (timeout, server failure, etc.)
            results["errors"].append(f"{rtype} error: {exc}")

    return results


# ── Subdomain ─────────────────────────────────────────────────────────────────

def _check_subdomain(sub: str, base: str) -> str | None:
    fqdn = f"{sub}.{base}"
    try:
        socket.setdefaulttimeout(1)
        socket.gethostbyname(fqdn)
        return fqdn
    except Exception:
        return None


def subdomain_scan(target: str) -> list[str]:
    found = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(_check_subdomain, sub, target): sub for sub in COMMON_SUBDOMAINS}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)
    return sorted(found)


# ── Port scan ─────────────────────────────────────────────────────────────────

def _check_port(host: str, port: int, timeout: float = 1.0) -> dict | None:
    """Check if a port is open with banner grabbing for common services."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((host, port)) == 0:
                banner = ""
                service_name = ""
                
                # Identify common services
                if port in (80, 8080, 8000, 8888, 8008):
                    service_name = "HTTP"
                    try:
                        s.settimeout(0.5)
                        s.send(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
                        banner = s.recv(256).decode(errors="replace").strip().split('\r\n')[0]
                    except Exception:
                        banner = "HTTP service detected"
                elif port == 443:
                    service_name = "HTTPS"
                    banner = "HTTPS (SSL/TLS)"
                elif port == 22:
                    service_name = "SSH"
                    try:
                        s.settimeout(0.5)
                        banner = s.recv(256).decode(errors="replace").strip()
                    except Exception:
                        banner = "SSH service"
                elif port == 3389:
                    service_name = "RDP"
                    banner = "Remote Desktop Protocol"
                elif port == 3306:
                    service_name = "MySQL"
                    banner = "MySQL database"
                elif port == 5432:
                    service_name = "PostgreSQL"
                    banner = "PostgreSQL database"
                elif port == 1433:
                    service_name = "MSSQL"
                    banner = "Microsoft SQL Server"
                elif port == 27017:
                    service_name = "MongoDB"
                    banner = "MongoDB"
                elif port == 6379:
                    service_name = "Redis"
                    banner = "Redis"
                elif port == 25:
                    service_name = "SMTP"
                    banner = "Mail server"
                elif port == 21:
                    service_name = "FTP"
                    banner = "FTP server"
                
                return {
                    "port": port,
                    "service": service_name or guess_service(port),
                    "banner": banner[:100] if banner else "Open port"
                }
    except socket.timeout:
        pass
    except Exception:
        pass
    return None

def guess_service(port: int) -> str:
    """Guess service name based on port number."""
    common_services = {
        80: "HTTP", 443: "HTTPS", 22: "SSH", 21: "FTP", 25: "SMTP",
        110: "POP3", 143: "IMAP", 993: "IMAPS", 995: "POP3S",
        3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB",
        6379: "Redis", 3389: "RDP", 5900: "VNC", 8080: "HTTP-Alt",
        8443: "HTTPS-Alt", 53: "DNS", 123: "NTP", 161: "SNMP"
    }
    return common_services.get(port, f"Port-{port}")

def port_scan(host: str, ports: list = None, timeout: float = 1.0, max_workers: int = 100) -> list[dict]:
    """
    Scan ports with configurable timeout and concurrency.
    
    Args:
        host: Target hostname or IP
        ports: List of ports to scan (uses COMMON_PORTS if None)
        timeout: Connection timeout in seconds
        max_workers: Maximum concurrent threads
    """
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        ip = host
    
    if ports is None:
        ports = COMMON_PORTS
    
    open_ports = []
    logger.info(f"[PortScan] Starting scan of {len(ports)} ports on {ip} with {max_workers} workers")
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_check_port, ip, p, timeout): p for p in ports}
        
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
                logger.info(f"[PortScan] Found open port: {result['port']} ({result.get('service', 'unknown')})")
    
    return sorted(open_ports, key=lambda x: x["port"])


# ── WHOIS ─────────────────────────────────────────────────────────────────────

def whois_lookup(target: str) -> str:
    import re
    import socket

    # Skip IPs and localhost
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    if ip_pattern.match(target) or target.lower() in ('localhost', 'localhost.localdomain', '127.0.0.1'):
        return "WHOIS lookup skipped for IP address or localhost."

    def _query_whois(server: str, query: str, port: int = 43) -> str:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((server, port))
            sock.send((query + "\r\n").encode())
            response = b""
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
            sock.close()
            return response.decode('utf-8', errors='replace')
        except Exception as e:
            return f"WHOIS query failed: {e}"

    try:
        # First attempt – Verisign server (works for .com, .net, .edu, etc.)
        resp = _query_whois("whois.verisign-grs.com", target)
        if "No match" in resp or "NOT FOUND" in resp:
            # Fallback to IANA generic server
            resp = _query_whois("whois.iana.org", target)

        if not resp or len(resp) < 50:
            return "No WHOIS data found for this domain."

        # Detect privacy protection
        if any(phrase in resp for phrase in ("WhoisPrivateRegistry", "REDACTED", "Privacy")):
            return "WHOIS privacy protection enabled – domain owner information hidden."

        return resp[:3000]  # Truncate for display

    except Exception as e:
        return f"WHOIS error: {e}"


# ── Background job fn ─────────────────────────────────────────────────────────

def _run_recon_job(target: str, provider: str, model: str, progress_cb=None):
    """Called in a background thread by JobManager."""
    import json
    from database import save_scan

    def cb(pct, msg):
        if progress_cb:
            progress_cb(pct, msg)

    cb(5, "Starting DNS enumeration…")
    dns_data = dns_lookup(target)

    cb(25, "Brute-forcing subdomains…")
    subdomains = subdomain_scan(target)

    cb(55, f"Scanning {len(COMMON_PORTS)} ports (this may take a minute)...")
    ports = port_scan(target)
    cb(65, f"Port scan complete. Found {len(ports)} open ports.")

    cb(75, "WHOIS lookup…")
    whois_text = whois_lookup(target)

    cb(85, "Sending to AI for analysis…")
    subdomain_lines = "\n".join(subdomains) if subdomains else "None found"
    port_lines = (
        "\n".join(f"  Port {p['port']}: OPEN  {p['banner']}" for p in ports)
        if ports else "No common ports open"
    )
    recon_summary = (
        f"TARGET: {target}\n\n"
        f"=== DNS Records ===\n"
        f"A Records: {dns_data['A']}\nMX Records: {dns_data['MX']}\nTXT Records: {dns_data['TXT']}\n"
        f"DNS Errors: {dns_data['errors']}\n\n"
        f"=== Discovered Subdomains ===\n{subdomain_lines}\n\n"
        f"=== Open Ports ===\n{port_lines}\n\n"
        f"=== WHOIS Data ===\n{whois_text[:2000]}"
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

    # Persist to DB
    save_scan(
        target=target,
        module_type="recon",
        ai_provider=provider,
        result_text=ai_result,
        tokens_used=tokens,
        cost_estimate=cost,
    )

    cb(100, "Done")
    return json.dumps({
        "target": target,
        "dns": dns_data,
        "subdomains": subdomains,
        "ports": ports,
        "whois": whois_text[:3000],
        "ai_analysis": ai_result,
        "raw_summary": recon_summary,
    })


# ── Flask routes ──────────────────────────────────────────────────────────────

@recon_bp.route("/", methods=["GET"])
def recon_page():
    return render_template("recon.html")


@recon_bp.route("/run", methods=["POST"])
def run_recon():
    """Submit recon job (async) and return job_id for polling."""
    data = request.get_json()
    target = (data.get("target") or "").strip()
    provider = data.get("provider", "ollama")
    model = data.get("model", "")

    if not target:
        return jsonify({"error": "No target specified."}), 400

    logger.info("[Recon] Submitting background job for: %s", target)
    job_id = get_manager().submit(_run_recon_job, target, provider, model)
    return jsonify({"job_id": job_id})
