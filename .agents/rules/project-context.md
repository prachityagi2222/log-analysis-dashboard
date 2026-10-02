---
trigger: always_on
description: "Core project plan for the Log Analysis Dashboard"
---
# Log Analysis Dashboard — Project Plan

## 1. What We're Building
A local-first, AI-powered log investigation dashboard that turns raw server logs into plain-English security reports in seconds — without sending data to the cloud.
**One-line pitch:** Upload a log file → get a summary of what happened, what's suspicious, and how bad it is.

## 2. The Problem
Security analysts spend 25–30 minutes manually reading logs to investigate one incident. There's too much data, alerts get ignored, and only senior analysts can interpret complex logs.
Existing tools don't solve this well:
• Cloud tools send your logs to external servers (privacy risk)
• Rule-based tools only catch known attacks
• Enterprise tools are expensive and complex

## 3. The Solution
1. User uploads a log file (SSH, web server, firewall) through a local web UI
2. System parses it into structured events
3. Two detection layers run:
   • Rules — catch known attacks (brute force, port scans)
   • ML (Isolation Forest) — catch unusual patterns rules miss
4. A local LLM writes a plain-English report with severity and MITRE ATT&CK tactic
5. Everything runs on the user's machine — no cloud, no API keys

## 4. Why It Matters
| Without | With |
|---|---|
| Manual log reading | Automated analysis |
| 30 min per investigation | Under 30 sec |
| Only experts can investigate | Anyone can understand the report |
| Logs sent to external servers | Everything stays local |
| Misses novel attacks | Catches known and unknown threats |

## 5. Tech Stack
| Layer | Choice |
|---|---|
| Language | Python 3.11+ |
| Backend | FastAPI |
| Database | SQLite + SQLAlchemy |
| Frontend | HTML + CSS + vanilla JS |
| Parsing | Python re + dateutil |
| ML | scikit-learn (Isolation Forest) |
| LLM | Ollama (real) + mock function (fallback) |

## 6. Database Schema
Four tables:
```
log_file
├── id
├── original_filename     (what the user called it)
├── raw_path              (where we saved their upload)
├── log_type              (ssh / web / firewall)
├── uploaded_at
└── owner_id              (reserved for future accounts)

parsed_file
├── id
├── log_file_id           → log_file
├── path                  (where the parsed JSON lives)
├── parser_version
└── created_at

detection
├── id
├── parsed_file_id        → parsed_file
├── method                ("rule" or "ml")
├── name                  ("brute_force", "ml_outlier_login")
├── severity              (low / medium / high / critical)
├── description           (one-line human summary)
├── mitre_tactic          (e.g. "Credential Access")
└── indices               (JSON list of event indices that triggered it)

report
├── id
├── parsed_file_id        → parsed_file
├── summary               (LLM's plain-English paragraph)
├── severity              (overall verdict)
├── tactics               (JSON list of MITRE tactics)
├── mode                  ("real" or "mock")
└── generated_at
```

Storage rule:
• Big files (raw log, parsed JSON) → disk
• Small structured data (metadata, detections, reports) → database

## 7. Data Pipeline
```
[1] Upload            ← user picks a file
[2] Save raw file     → data/raw/<id>.log
[3] Detect log type   (ssh / web / firewall)
[4] Parse to JSON     → data/parsed/<id>.json
[5] Rule engine       → detections (method="rule")
[6] Feature extraction (turn events into numeric features)
[7] ML model          → detections (method="ml")
[8] Collect detections
[9] LLM report        → summary + severity + tactics
[10] Display results
```
Steps 1 and 10 are user-facing. The rest run invisibly in the background.

## 8. Screens (MVP)
### Screen 1 — Upload
• App title
• Drag-and-drop zone ("Drop your log file here")
• Recent uploads list
### Screen 2 — Results
• Filename + overall severity badge
• Summary paragraph (from the report)
• Findings table (detections): name, severity, tactic
• Click a row → Screen 3
### Screen 3 — Detection Detail
• Full detection info
• Raw log lines that triggered it (from indices)
### Screen 4 — Full Report
• Complete summary
• Severity, tactics, mode, timestamp

## 9. MVP Definition
Minimum viable product:
Upload a file → get a report and a list of detections shown on screen.
Everything else (accounts, multi-user, exports, charts) is post-MVP.

## 10. What's Explicitly NOT in MVP
• User accounts / login (reserved via owner_id, not built)
• Cloud sync
• Real-time log streaming
• Support for every log format ever (start with SSH + web + firewall)
• Charts/visualizations
• Email/Slack alerts
