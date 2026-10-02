# Log Analysis Dashboard

> **⬇️ [Download the Windows installer (v1.0.0)](https://github.com/prachityagi2222/log-analysis-dashboard/releases/latest)**  
> Just download the `.exe`, run it, and launch from the Start Menu. No Python, Rust, or setup required.

> ⚠️ Windows SmartScreen may warn because the installer is unsigned. Click **"More info" → "Run anyway"** to proceed.

> **Local-First, AI-Powered Log Investigation Dashboard**  
> Turn raw server logs into plain-English security reports in seconds — 100% on your machine without cloud exposure or API keys.

---

## 🚀 Key Features

- **Local-First Privacy**: Never sends logs to external servers or third-party cloud services.
- **Multi-Format Log Parser**: Automatically detects and parses **SSH (auth.log)**, **Web (Nginx / Apache CLF/Combined)**, and **Firewall (UFW / iptables)** logs.
- **Dual Detection Engine**:
  - **Rule Engine**: Catches known attacks (SSH brute force, user enumeration, SQL injection, directory traversal/LFI, OS command injection, port scans, and packet floods) and tags them with **MITRE ATT&CK** tactics.
  - **Machine Learning (Isolation Forest)**: Identifies anomalous event clusters based on access timing, payload entropy, and frequency deviations that rules miss.
- **AI Security Analyst Reports**:
  - Direct integration with local **Ollama** LLMs (e.g. `llama3`, `mistral`).
  - Automatic zero-configuration fallback to an intelligent local mock report generator if Ollama is not running.
- **Zero-Build Vanilla UI**: Fast, responsive 4-screen Single Page Application built with HTML, CSS, and Vanilla JavaScript.

---

## 🏗️ Architecture & Data Pipeline

```
[1] Upload File  ──>  [2] Save Raw Log (data/raw/<id>.log)
                           │
                           ▼
                      [3] Detect Log Type (SSH / Web / Firewall)
                           │
                           ▼
                      [4] Parse to Structured JSON (data/parsed/<id>.json)
                           │
               ┌───────────┴───────────┐
               ▼                       ▼
      [5] Rule Engine        [6] Feature Extraction
   (MITRE ATT&CK Catalog)              │
               │                       ▼
               │             [7] Isolation Forest ML
               └───────────┬───────────┘
                           │
                           ▼
                 [8] Collect Detections
                           │
                           ▼
                 [9] Local LLM / Fallback Report
                           │
                           ▼
                [10] Display Results in Web UI
```

---

## 🗄️ Database Schema (SQLite)

- **`log_file`**: Upload metadata (`original_filename`, `raw_path`, `log_type`, `uploaded_at`, `owner_id`).
- **`parsed_file`**: Parsed reference (`log_file_id`, `path`, `parser_version`, `created_at`).
- **`detection`**: Findings (`parsed_file_id`, `method`, `name`, `severity`, `description`, `mitre_tactic`, `indices`).
- **`report`**: Plain-English incident analysis (`parsed_file_id`, `summary`, `severity`, `tactics`, `mode`, `generated_at`).

---

## 🖥️ Screen Layout (MVP)

1. **Screen 1 — Upload**: Drag-and-drop zone, sample log quick-loaders, and recent investigation history.
2. **Screen 2 — Results**: Severity banner, AI incident summary, MITRE tactic badges, and interactive findings table.
3. **Screen 3 — Detection Detail**: Detailed detection description with raw log lines highlighted with line numbers.
4. **Screen 4 — Full Report**: Printable executive summary, audit trail, and tactic breakdown.

---

## ⚡ Quick Start

### 1. Requirements
- Python 3.11+ (Python 3.13 tested)
- Dependencies installed via `requirements.txt`

### 2. Setup & Virtual Environment
```bash
# Activate venv
.\venv\Scripts\activate

# Install requirements (if setting up fresh)
pip install -r requirements.txt
```

### 3. Run the Dashboard
```bash
python run.py
```
Open **[http://127.0.0.1:8080](http://127.0.0.1:8080)** in your browser.

### 4. Run Automated Test Suite
```bash
python test_server.py
```

---

## 🧪 Testing with Sample Logs
The `sample_logs/` folder contains pre-configured test logs:
- `ssh_brute_force.log`: Multi-user SSH brute force & root targeting.
- `web_attacks.log`: SQL injection, directory traversal (`/etc/passwd`), and endpoint scanning.
- `firewall_port_scan.log`: Multi-port reconnaissance scan & dropped traffic.

You can click the sample buttons directly in the dashboard UI on **Screen 1** to test instantly!
