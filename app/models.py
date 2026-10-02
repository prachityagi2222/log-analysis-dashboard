from datetime import datetime
import json
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base


class LogFile(Base):
    __tablename__ = "log_file"

    id = Column(Integer, primary_key=True, index=True)
    original_filename = Column(String, nullable=False)
    raw_path = Column(String, nullable=False)
    log_type = Column(String, nullable=False)  # ssh / web / firewall
    uploaded_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    owner_id = Column(String, nullable=True)  # reserved for future accounts

    parsed_files = relationship("ParsedFile", back_populates="log_file", cascade="all, delete-orphan")


class ParsedFile(Base):
    __tablename__ = "parsed_file"

    id = Column(Integer, primary_key=True, index=True)
    log_file_id = Column(Integer, ForeignKey("log_file.id"), nullable=False)
    path = Column(String, nullable=False)  # where the parsed JSON lives
    parser_version = Column(String, default="1.0.0", nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    log_file = relationship("LogFile", back_populates="parsed_files")
    detections = relationship("Detection", back_populates="parsed_file", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="parsed_file", cascade="all, delete-orphan")


class Detection(Base):
    __tablename__ = "detection"

    id = Column(Integer, primary_key=True, index=True)
    parsed_file_id = Column(Integer, ForeignKey("parsed_file.id"), nullable=False)
    method = Column(String, nullable=False)  # "rule" or "ml"
    name = Column(String, nullable=False)  # "brute_force", "ml_outlier_login", etc.
    severity = Column(String, nullable=False)  # low / medium / high / critical
    description = Column(String, nullable=False)  # one-line human summary
    mitre_tactic = Column(String, nullable=False)  # e.g. "Credential Access"
    indices = Column(Text, nullable=False, default="[]")  # JSON list of event indices that triggered it

    parsed_file = relationship("ParsedFile", back_populates="detections")

    @property
    def indices_list(self):
        try:
            return json.loads(self.indices) if self.indices else []
        except Exception:
            return []


class Report(Base):
    __tablename__ = "report"

    id = Column(Integer, primary_key=True, index=True)
    parsed_file_id = Column(Integer, ForeignKey("parsed_file.id"), nullable=False)
    summary = Column(Text, nullable=False)  # LLM's plain-English paragraph
    severity = Column(String, nullable=False)  # overall verdict: low / medium / high / critical / info
    tactics = Column(Text, nullable=False, default="[]")  # JSON list of MITRE tactics
    mode = Column(String, nullable=False)  # "real" or "mock"
    generated_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    parsed_file = relationship("ParsedFile", back_populates="reports")

    @property
    def tactics_list(self):
        try:
            return json.loads(self.tactics) if self.tactics else []
        except Exception:
            return []
