import json
import os
import shutil
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, UploadFile, File, Form, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from app.config import BASE_DIR, RAW_DIR, PARSED_DIR, STATIC_DIR, SAMPLE_DIR
from app.database import get_db, init_db
from app.models import LogFile, ParsedFile, Detection, Report
from app.schemas import (
    AnalysisResponse,
    LogFileListItem,
    DetectionOut,
    DetectionDetailOut,
    ReportOut,
)
from app.parsing.parser_service import parse_log_file, save_parsed_events, load_parsed_events, PARSER_VERSION
from app.detection.rule_engine import RuleEngine
from app.detection.ml_engine import MLEngine
from app.reporting.llm_service import generate_llm_report

# Initialize database tables on startup
init_db()

app = FastAPI(
    title="Log Analysis Dashboard API",
    description="Local-first AI-powered security log investigation dashboard",
    version="1.0.0"
)

# CORS middleware for development ease
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

rule_engine = RuleEngine()
ml_engine = MLEngine(contamination=0.08)


@app.post("/api/upload", response_model=AnalysisResponse)
async def upload_log(
    file: UploadFile = File(...),
    log_type: Optional[str] = Form(None),
    db: Session = Depends(get_db)
):
    """
    Executes the complete Data Pipeline (Section 7):
    [1] Upload
    [2] Save raw file -> data/raw/<id>.log
    [3] Detect log type (ssh / web / firewall)
    [4] Parse to JSON -> data/parsed/<id>.json
    [5] Rule engine -> detections
    [6] Feature extraction & ML model -> detections
    [7] Collect detections
    [8] LLM report -> summary + severity + tactics
    [9] Store structured metadata in SQLite
    [10] Return results for display
    """
    original_filename = file.filename or "unknown.log"
    
    # [1] Create preliminary LogFile database record to get an ID
    log_record = LogFile(
        original_filename=original_filename,
        raw_path="",
        log_type="unknown"
    )
    db.add(log_record)
    db.flush()

    # [2] Save raw file to disk
    file_ext = Path(original_filename).suffix or ".log"
    safe_raw_path = RAW_DIR / f"{log_record.id}_{Path(original_filename).stem}{file_ext}"
    with open(safe_raw_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    
    log_record.raw_path = str(safe_raw_path)

    # [3] Detect log type & [4] Parse to JSON
    detected_type, events = parse_log_file(safe_raw_path, forced_type=log_type)
    log_record.log_type = detected_type

    # Create ParsedFile record
    parsed_record = ParsedFile(
        log_file_id=log_record.id,
        path="",
        parser_version=PARSER_VERSION
    )
    db.add(parsed_record)
    db.flush()

    # Save parsed JSON to disk
    parsed_json_path = save_parsed_events(parsed_record.id, events)
    parsed_record.path = str(parsed_json_path)

    # [5] Rule engine detections
    rule_detections = rule_engine.run(detected_type, events)

    # [6] & [7] Feature extraction & ML model detections
    ml_detections = ml_engine.run(events)

    # [8] Collect detections
    all_detections_data = rule_detections + ml_detections
    saved_detection_models = []

    for d in all_detections_data:
        det_record = Detection(
            parsed_file_id=parsed_record.id,
            method=d["method"],
            name=d["name"],
            severity=d["severity"],
            description=d["description"],
            mitre_tactic=d["mitre_tactic"],
            indices=json.dumps(d["indices"])
        )
        db.add(det_record)
        saved_detection_models.append(det_record)

    db.flush()

    # [9] LLM report generation (Ollama with mock fallback)
    summary_text, overall_severity, tactics_list, mode = generate_llm_report(
        log_type=detected_type,
        original_filename=original_filename,
        total_events=len(events),
        detections=all_detections_data
    )

    report_record = Report(
        parsed_file_id=parsed_record.id,
        summary=summary_text,
        severity=overall_severity,
        tactics=json.dumps(tactics_list),
        mode=mode
    )
    db.add(report_record)

    db.commit()
    db.refresh(log_record)
    db.refresh(parsed_record)
    db.refresh(report_record)

    # Prepare response
    detection_outs = [
        DetectionOut(
            id=dm.id,
            parsed_file_id=dm.parsed_file_id,
            method=dm.method,
            name=dm.name,
            severity=dm.severity,
            description=dm.description,
            mitre_tactic=dm.mitre_tactic,
            indices=dm.indices_list
        )
        for dm in saved_detection_models
    ]

    report_out = ReportOut(
        id=report_record.id,
        parsed_file_id=report_record.parsed_file_id,
        summary=report_record.summary,
        severity=report_record.severity,
        tactics=report_record.tactics_list,
        mode=report_record.mode,
        generated_at=report_record.generated_at
    )

    return AnalysisResponse(
        log_file_id=log_record.id,
        parsed_file_id=parsed_record.id,
        original_filename=log_record.original_filename,
        log_type=log_record.log_type,
        uploaded_at=log_record.uploaded_at,
        report=report_out,
        detections=detection_outs,
        total_events=len(events),
        events_preview=events[:10]
    )


@app.get("/api/logs", response_model=List[LogFileListItem])
def list_logs(db: Session = Depends(get_db)):
    """
    Returns list of recently uploaded logs for Screen 1.
    """
    logs = db.query(LogFile).order_by(LogFile.uploaded_at.desc()).limit(30).all()
    results = []

    for log in logs:
        parsed = log.parsed_files[0] if log.parsed_files else None
        severity = "unknown"
        det_count = 0
        event_count = 0

        if parsed:
            det_count = len(parsed.detections)
            if parsed.reports:
                severity = parsed.reports[0].severity
            # Read event count from parsed JSON file
            try:
                events = load_parsed_events(parsed.path)
                event_count = len(events)
            except Exception:
                event_count = 0

        results.append(
            LogFileListItem(
                id=log.id,
                original_filename=log.original_filename,
                log_type=log.log_type,
                uploaded_at=log.uploaded_at,
                severity=severity,
                detection_count=det_count,
                event_count=event_count
            )
        )
    return results


@app.get("/api/analysis/{log_file_id}", response_model=AnalysisResponse)
def get_analysis(log_file_id: int, db: Session = Depends(get_db)):
    """
    Retrieves full analysis for a given log file.
    """
    log_file = db.query(LogFile).filter(LogFile.id == log_file_id).first()
    if not log_file or not log_file.parsed_files:
        raise HTTPException(status_code=404, detail="Log file or analysis not found")

    parsed = log_file.parsed_files[0]
    report = parsed.reports[0] if parsed.reports else None
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    events = load_parsed_events(parsed.path)

    detection_outs = [
        DetectionOut(
            id=d.id,
            parsed_file_id=d.parsed_file_id,
            method=d.method,
            name=d.name,
            severity=d.severity,
            description=d.description,
            mitre_tactic=d.mitre_tactic,
            indices=d.indices_list
        )
        for d in parsed.detections
    ]

    report_out = ReportOut(
        id=report.id,
        parsed_file_id=report.parsed_file_id,
        summary=report.summary,
        severity=report.severity,
        tactics=report.tactics_list,
        mode=report.mode,
        generated_at=report.generated_at
    )

    return AnalysisResponse(
        log_file_id=log_file.id,
        parsed_file_id=parsed.id,
        original_filename=log_file.original_filename,
        log_type=log_file.log_type,
        uploaded_at=log_file.uploaded_at,
        report=report_out,
        detections=detection_outs,
        total_events=len(events),
        events_preview=events[:10]
    )


@app.get("/api/detection/{detection_id}/detail", response_model=DetectionDetailOut)
def get_detection_detail(detection_id: int, db: Session = Depends(get_db)):
    """
    Screen 3: Full detection info with raw log lines that triggered it (from indices).
    """
    detection = db.query(Detection).filter(Detection.id == detection_id).first()
    if not detection:
        raise HTTPException(status_code=404, detail="Detection not found")

    parsed = detection.parsed_file
    events = load_parsed_events(parsed.path)

    indices = detection.indices_list
    matched_events = []
    raw_lines = []

    # Map events by index
    event_map = {e["index"]: e for e in events if "index" in e}
    for idx in indices:
        if idx in event_map:
            ev = event_map[idx]
            matched_events.append(ev)
            raw_lines.append(ev.get("raw", ""))

    return DetectionDetailOut(
        id=detection.id,
        parsed_file_id=detection.parsed_file_id,
        method=detection.method,
        name=detection.name,
        severity=detection.severity,
        description=detection.description,
        mitre_tactic=detection.mitre_tactic,
        indices=indices,
        raw_lines=raw_lines,
        matched_events=matched_events
    )


@app.get("/api/report/{parsed_file_id}", response_model=ReportOut)
def get_report(parsed_file_id: int, db: Session = Depends(get_db)):
    """
    Screen 4: Complete report details.
    """
    report = db.query(Report).filter(Report.parsed_file_id == parsed_file_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    return ReportOut(
        id=report.id,
        parsed_file_id=report.parsed_file_id,
        summary=report.summary,
        severity=report.severity,
        tactics=report.tactics_list,
        mode=report.mode,
        generated_at=report.generated_at
    )


# Sample Logs Provider
@app.get("/sample/{sample_name}")
def get_sample_log(sample_name: str):
    sample_file = SAMPLE_DIR / sample_name
    if not sample_file.exists():
        raise HTTPException(status_code=404, detail="Sample log not found")
    return FileResponse(sample_file, media_type="text/plain", filename=sample_name)


# Serve Static UI
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
def serve_index():
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return {"message": "Log Analysis Dashboard Backend is Running"}
