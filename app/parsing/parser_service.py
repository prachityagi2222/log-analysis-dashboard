import json
from pathlib import Path
from typing import List, Dict, Any, Tuple
from app.parsing.detector import detect_log_type
from app.parsing.ssh_parser import parse_ssh_lines
from app.parsing.web_parser import parse_web_lines
from app.parsing.firewall_parser import parse_firewall_lines
from app.config import PARSED_DIR

PARSER_VERSION = "1.0.0"


def parse_log_file(file_path: Path, forced_type: str = None) -> Tuple[str, List[Dict[str, Any]]]:
    """
    Reads the file, detects log type (or uses forced_type),
    and parses into structured event list.
    """
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    log_type = forced_type if forced_type and forced_type != "unknown" else detect_log_type(lines)

    if log_type == "ssh":
        events = parse_ssh_lines(lines)
    elif log_type == "web":
        events = parse_web_lines(lines)
    elif log_type == "firewall":
        events = parse_firewall_lines(lines)
    else:
        # Fallback to SSH or generic parsing
        events = parse_ssh_lines(lines)
        log_type = "ssh"

    return log_type, events


def save_parsed_events(parsed_id: int, events: List[Dict[str, Any]]) -> Path:
    """
    Saves parsed event JSON into data/parsed/<parsed_id>.json.
    """
    out_path = PARSED_DIR / f"{parsed_id}.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(events, f, indent=2)
    return out_path


def load_parsed_events(path_str: str) -> List[Dict[str, Any]]:
    """
    Loads parsed events from json file.
    """
    path = Path(path_str)
    if not path.exists():
        return []
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)
