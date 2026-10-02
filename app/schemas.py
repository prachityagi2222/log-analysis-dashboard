from datetime import datetime
from typing import List, Optional, Any
from pydantic import BaseModel


class DetectionBase(BaseModel):
    method: str
    name: str
    severity: str
    description: str
    mitre_tactic: str
    indices: List[int]


class DetectionOut(DetectionBase):
    id: int
    parsed_file_id: int

    class Config:
        from_attributes = True


class DetectionDetailOut(DetectionOut):
    raw_lines: List[str]
    matched_events: List[dict]


class ReportOut(BaseModel):
    id: int
    parsed_file_id: int
    summary: str
    severity: str
    tactics: List[str]
    mode: str
    generated_at: datetime

    class Config:
        from_attributes = True


class LogFileListItem(BaseModel):
    id: int
    original_filename: str
    log_type: str
    uploaded_at: datetime
    severity: Optional[str] = "unknown"
    detection_count: int = 0
    event_count: int = 0

    class Config:
        from_attributes = True


class AnalysisResponse(BaseModel):
    log_file_id: int
    parsed_file_id: int
    original_filename: str
    log_type: str
    uploaded_at: datetime
    report: ReportOut
    detections: List[DetectionOut]
    total_events: int
    events_preview: List[dict]
