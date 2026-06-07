<div align="center">
  
  <img src="https://raw.githubusercontent.com/Ronald-PH/caio/main/images/caio.png" alt="CAIO Logo" width="100%">
  
  # CAIO — Cybersecurity AI Orchestrator
  
  [![Version](https://img.shields.io/badge/version-1.0.0-f43f5e?style=for-the-badge&logo=github)](https://github.com/Ronald-PH/caio)
  [![Python](https://img.shields.io/badge/Python-3.11+-22d3ee?style=for-the-badge&logo=python)](https://python.org)
  [![License](https://img.shields.io/badge/License-MIT-a78bfa?style=for-the-badge&logo=opensource)](https://opensource.org/licenses/MIT)
  [![Stars](https://img.shields.io/github/stars/Ronald-PH/caio?style=for-the-badge&logo=github&color=f59e0b)](https://github.com/Ronald-PH/caio/stargazers)
  
  [![Ollama](https://img.shields.io/badge/Ollama-✓-22c55e?style=flat-square&logo=ollama)](https://ollama.com)
  [![OpenAI](https://img.shields.io/badge/OpenAI-✓-f59e0b?style=flat-square&logo=openai)](https://openai.com)
  [![Claude](https://img.shields.io/badge/Claude-✓-f43f5e?style=flat-square&logo=anthropic)](https://anthropic.com)
  
  > **AI-Powered Security Platform | Reconnaissance | Log Analysis | Incident Response**
  
</div>

<br>

## 📌 Overview

CAIO is your AI-powered cybersecurity sidekick. Whether you're a SOC analyst drowning in alerts, a pentester mapping out attack surfaces, or a sysadmin trying to keep things locked down, CAIO helps you work smarter. It automates the boring stuff — recon, log hunting, vulnerability checks, incident response — so you can focus on what actually matters: stopping threats.

**License:** MIT  
**Platform:** Windows 11 / Linux / macOS

---

## ✨ Features

### Core Security Modules

| Module                       | Description                                                                                          |
| ---------------------------- | ---------------------------------------------------------------------------------------------------- |
| **Reconnaissance**           | DNS enumeration, subdomain discovery, port scanning, WHOIS lookup — all analyzed by AI               |
| **Log Analysis**             | Paste any log (Windows Event, Apache, Syslog, Firewall) → AI identifies IOCs, TTPs, attack patterns  |
| **Vulnerability Assessment** | URL probing or file upload (Dockerfile, Python, JS, configs) → AI-powered security review            |
| **IR Chat**                  | Multi-turn incident response assistant with DFIR expertise, MITRE ATT&CK mapping, command references |

### Threat Intelligence

| Module                    | Description                                                                          |
| ------------------------- | ------------------------------------------------------------------------------------ |
| **OSINT Profiler**        | Build threat dossiers from GitHub, Certificate Transparency logs, and public sources |
| **Email Forensics**       | Parse email headers, detect spoofing, analyze SPF/DKIM/DMARC, identify phishing      |
| **Password Auditor**      | Analyze password entropy, detect patterns, check against breach dictionaries         |
| **CVE Intelligence Feed** | Live NVD lookup with AI contextualization and patch priority scoring                 |

### Detection & Response

| Module                    | Description                                                                            |
| ------------------------- | -------------------------------------------------------------------------------------- |
| **SIEM Rule Generator**   | Convert attack descriptions into Sigma, Splunk SPL, KQL (Sentinel), and Suricata rules |
| **Supply Chain Risk**     | Assess third-party vendors for CVEs, breach history, and trust indicators              |
| **Threat Actor Profiler** | Correlate IOCs/TTPs with known APT groups and MITRE ATT&CK techniques                  |

### Advanced Analysis

| Module                   | Description                                                                         |
| ------------------------ | ----------------------------------------------------------------------------------- |
| **Payload DNA Analyzer** | Deobfuscate and analyze suspicious code (Base64, PowerShell, shellcode, VBA macros) |
| **Network Storyteller**  | Convert network logs into plain-English attack narratives with timelines            |
| **Honeypot Simulator**   | Generate realistic attack logs for training and SIEM testing                        |
| **Red Team Playbook**    | Generate structured adversary emulation plans based on target profiles              |

### Operations & Analytics

| Module                | Description                                                                      |
| --------------------- | -------------------------------------------------------------------------------- |
| **Batch Scanner**     | Run reconnaissance or vulnerability scans against multiple targets concurrently  |
| **Compliance Report** | Map findings to NIST 800-53, ISO 27001, or PCI DSS with gap analysis             |
| **Scan History**      | Every scan persisted to SQLite — searchable, filterable, exportable              |
| **Cost Dashboard**    | Track token usage and USD costs per provider/module with Chart.js visualizations |

---

## 🖥️ AI Provider Support

| Provider             | Type         | Cost Tracking            | Notes                 |
| -------------------- | ------------ | ------------------------ | --------------------- |
| **Ollama**           | Local (free) | Token count only         | Runs entirely offline |
| **OpenAI GPT-4o**    | Cloud (paid) | Input/output token costs | Requires API key      |
| **Anthropic Claude** | Cloud (paid) | Input/output token costs | Requires API key      |

---

## 🖼️ Screenshots

<div align="center">
  <img src="https://raw.githubusercontent.com/Ronald-PH/caio/main/images/main-dashboard.png" alt="CAIO Dashboard" width="80%">
  <br>
  <em>Main Dashboard</em>
</div>

---

## 🚀 Quick Start

### Prerequisites

- Python 3.10 or higher
- Git (optional)
- Ollama (for local AI — recommended)

### Windows 11 Installation

**1. Clone or download the repository**

```cmd
git clone https://github.com/Ronald-PH/caio.git
cd caio
```

**2. Create a virtual environment**

```cmd
python -m venv venv
venv\Scripts\activate
```

**3. Install dependencies**

```cmd
pip install -r requirements.txt
```

**4. Configure environment variables**

```cmd
copy .env.example .env
notepad .env
```

Edit the `.env` file:

- Set `SECRET_KEY` to a random string
- Add `OPENAI_API_KEY` and/or `ANTHROPIC_API_KEY` if using cloud providers
- For local inference, leave API keys blank

**5. Set up Ollama (recommended for local AI)**

1. Download from [ollama.com](https://ollama.com/) and install
2. Open a new terminal and run:
   ```cmd
   ollama serve
   ```
3. In another terminal, pull a model:
   ```cmd
   ollama pull llama3.2
   ```
   Other good options: `mistral`, `phi3`, `llama3.1:8b`, `codellama`

**6. Run CAIO**

```cmd
python app.py
```

Open your browser to: **http://127.0.0.1:5000**

---

## 📁 Project Structure

<pre>
caio/
├── app.py                      # Flask application factory + routes
├── database.py                 # SQLite setup, queries, cost statistics
├── requirements.txt            # Python dependencies
├── .env.example                # Environment variable template
├── README.md                   # This file
│
├── modules/                    # Backend blueprints
│   ├── __init__.py
│   ├── ai_client.py            # Unified AI caller (Ollama/OpenAI/Claude)
│   ├── jobs.py                 # Background job manager (threading + SQLite)
│   ├── recon.py                # Reconnaissance module
│   ├── log_analysis.py         # Log analysis module
│   ├── vuln_scan.py            # Vulnerability assessment
│   ├── chat.py                 # Incident response chat
│   ├── osint_profiler.py       # OSINT threat dossiers
│   ├── email_forensics.py      # Email header analysis
│   ├── password_auditor.py     # Password policy auditing
│   ├── cve_feed.py             # CVE intelligence
│   ├── siem_rule_generator.py  # Sigma/SPL/KQL/Suricata rules
│   ├── supply_chain_risk.py    # Third-party risk assessment
│   ├── threat_profiler.py      # Threat actor attribution
│   ├── payload_dna.py          # Malicious code analysis
│   ├── network_storyteller.py  # Network attack narration
│   ├── honeypot_simulator.py   # Fake attack log generation
│   ├── redteam_playbook.py     # Red team engagement plans
│   ├── batch_scanner.py        # Multi-target batch scanning
│   ├── compliance_report.py    # Framework gap analysis
│   ├── settings.py             # Configuration management
│   └── dashboard.py            # Landing page
│
├── templates/                  # Jinja2 HTML templates
│   ├── base.html               # Base layout with sidebar + theme toggle
│   ├── index.html              # Dashboard
│   ├── recon.html              # Reconnaissance page
│   ├── log_analysis.html       # Log analysis page
│   ├── vuln_scan.html          # Vulnerability assessment
│   ├── chat.html               # IR chat interface
│   ├── history.html            # Scan history with filtering
│   ├── cost_dashboard.html     # Cost analytics with Chart.js
│   ├── settings.html           # Configuration page
│   ├── batch_scanner.html      # Batch scanning interface
│   ├── compliance_report.html  # Compliance report generator
│   ├── cve_feed.html           # CVE lookup
│   ├── email_forensics.html    # Email analysis
│   ├── honeypot_simulator.html # Log simulator
│   ├── network_storyteller.html
│   ├── osint_profiler.html
│   ├── password_auditor.html
│   ├── payload_dna.html
│   ├── redteam_playbook.html
│   ├── siem_rule_generator.html
│   ├── supply_chain_risk.html
│   ├── threat_profiler.html
│   └── pdf_export.html         # PDF report template
│
└── static/
    └── style.css               # Cyber-noir theme (dark/light modes)
</pre>

---

## 🔌 API Endpoints

| Endpoint               | Method | Description                                                  |
| ---------------------- | ------ | ------------------------------------------------------------ |
| `/health`              | GET    | JSON health status for all AI providers                      |
| `/progress/<job_id>`   | GET    | Poll background job status (used by recon)                   |
| `/history`             | GET    | Scan history with filtering (module, provider, target, days) |
| `/history/<id>`        | GET    | Full scan detail as JSON                                     |
| `/history/<id>/delete` | POST   | Delete a scan record                                         |
| `/cost-dashboard`      | GET    | Cost analytics page                                          |
| `/cost-dashboard/api`  | GET    | Cost analytics as JSON                                       |
| `/export/pdf/<id>`     | GET    | Download scan as PDF                                         |

### Module Routes (each with `/` and POST endpoints)

- `/recon/*` — Reconnaissance
- `/log-analysis/*` — Log analysis
- `/vuln-scan/*` — Vulnerability assessment
- `/chat/*` — IR chat
- `/osint-profiler/*` — OSINT threat dossiers
- `/email-forensics/*` — Email header forensics
- `/password-auditor/*` — Password auditing
- `/cve-feed/*` — CVE intelligence
- `/siem-rules/*` — SIEM rule generation
- `/supply-chain/*` — Supply chain risk
- `/threat-profiler/*` — Threat actor attribution
- `/payload-dna/*` — Malicious code analysis
- `/network-storyteller/*` — Network attack narration
- `/honeypot-simulator/*` — Honeypot log simulation
- `/redteam-playbook/*` — Red team playbooks
- `/batch/*` — Batch scanning
- `/compliance/*` — Compliance reporting
- `/settings/*` — Configuration management

---

## 📊 Cost Dashboard

CAIO tracks token usage and costs for all API calls:

- **OpenAI:** Configurable rates (default: $0.005/1K input, $0.015/1K output)
- **Claude:** Configurable rates (default: $0.003/1K input, $0.015/1K output)
- **Ollama:** Free (token counting only)

The dashboard displays:

- Total cost over 30 days
- Cost breakdown by provider
- Cost breakdown by module
- Daily cost trend chart
- Recent cost details table

---

## 📄 PDF Export

CAIO attempts PDF export in this order:

1. **weasyprint** — Pure Python, best quality (requires GTK3 runtime on Windows)
2. **pdfkit** — Wrapper for `wkhtmltopdf`
3. **HTML fallback** — Print-friendly HTML (Ctrl+P → Save as PDF)

---

## 🛡️ Security & Legal Notice

CAIO is a **defensive security tool** intended for:

- Security professionals conducting authorized assessments
- SOC analysts investigating incidents
- System owners reviewing their own infrastructure
- Educational and research purposes

**⚠️ IMPORTANT:**

- Only scan, test, or analyze systems you own or have explicit written permission to test
- Unauthorized scanning is illegal in most jurisdictions
- The author assumes no liability for misuse of this tool
- Always follow responsible disclosure practices

---

## 💬 Support

- 🐛 [Report a Bug](https://github.com/Ronald-PH/caio/issues)
- 💡 [Feature Request](https://github.com/Ronald-PH/caio/issues)
- 📖 [Documentation](https://github.com/Ronald-PH/caio/wiki)
- 💬 [Discussions](https://github.com/Ronald-PH/caio/discussions)

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

For bugs or feature requests, please open an issue on GitHub.

---

## 📧 Contact

For any inquiries or support, please reach out to
<br>
**GitHub:** [https://github.com/Ronald-PH](https://github.com/Ronald-PH)  
**Project:** [https://github.com/Ronald-PH/caio](https://github.com/Ronald-PH/caio)

---

## 🙏 Acknowledgments

- [Ollama](https://ollama.com/) — Local LLM inference
- [OpenAI](https://openai.com/) — GPT-4o API
- [Anthropic](https://anthropic.com/) — Claude API
- [Flask](https://flask.palletsprojects.com/) — Web framework
- [Bootstrap](https://getbootstrap.com/) — UI components
- [Chart.js](https://www.chartjs.org/) — Data visualization
- [Highlight.js](https://highlightjs.org/) — Code syntax highlighting

---

## 📜 License

MIT License — see [LICENSE](LICENSE) file for details.

---

<div align="center">
  
  **[Report Bug](https://github.com/Ronald-PH/caio/issues)** · **[Request Feature](https://github.com/Ronald-PH/caio/issues)** · **[Star on GitHub](https://github.com/Ronald-PH/caio)**
  
  *Built with ❤️ for the cybersecurity community*
  
</div>
