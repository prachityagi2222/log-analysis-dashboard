import re
from datetime import datetime
from typing import List, Dict, Any, Optional
from dateutil import parser as date_parser


def parse_firewall_timestamp(ts_str: str) -> Optional[str]:
    try:
        dt = date_parser.parse(ts_str)
        return dt.isoformat()
    except Exception:
        return None


def parse_firewall_lines(lines: List[str]) -> List[Dict[str, Any]]:
    events = []

    # Timestamp pattern (syslog style: Oct 02 14:10:05 or ISO 2026-10-02T14:10:05)
    ts_re = re.compile(
        r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2})"
    )

    action_re = re.compile(r"\[UFW\s+(?P<ufw_act>BLOCK|ALLOW|AUDIT)\]|\b(?P<act>DROP|REJECT|ACCEPT|BLOCK)\b", re.IGNORECASE)
    src_re = re.compile(r"SRC=(?P<src>\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+)")
    dst_re = re.compile(r"DST=(?P<dst>\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+)")
    proto_re = re.compile(r"PROTO=(?P<proto>[A-Za-z0-9]+)")
    spt_re = re.compile(r"SPT=(?P<spt>\d+)")
    dpt_re = re.compile(r"DPT=(?P<dpt>\d+)")
    in_re = re.compile(r"IN=(?P<in>[a-zA-Z0-9_\-\.]*)")
    out_re = re.compile(r"OUT=(?P<out>[a-zA-Z0-9_\-\.]*)")

    for idx, raw_line in enumerate(lines):
        line = raw_line.strip()
        if not line:
            continue

        ts_match = ts_re.search(line)
        timestamp = parse_firewall_timestamp(ts_match.group("timestamp")) if ts_match else datetime.utcnow().isoformat()

        act_match = action_re.search(line)
        if act_match:
            action = (act_match.group("ufw_act") or act_match.group("act") or "DROP").upper()
        else:
            action = "DROP" if "block" in line.lower() or "drop" in line.lower() else "ALLOW"

        src_match = src_re.search(line)
        dst_match = dst_re.search(line)
        proto_match = proto_re.search(line)
        spt_match = spt_re.search(line)
        dpt_match = dpt_re.search(line)
        in_match = in_re.search(line)
        out_match = out_re.search(line)

        source_ip = src_match.group("src") if src_match else "unknown"
        dest_ip = dst_match.group("dst") if dst_match else "unknown"
        protocol = proto_match.group("proto").upper() if proto_match else "TCP"
        source_port = int(spt_match.group("spt")) if spt_match else None
        dest_port = int(dpt_match.group("dpt")) if dpt_match else None

        is_blocked = action in ("BLOCK", "DROP", "REJECT")
        status = "failure" if is_blocked else "success"

        event = {
            "index": idx,
            "raw": line,
            "timestamp": timestamp or datetime.utcnow().isoformat(),
            "service": "firewall",
            "action": action,
            "status": status,
            "source_ip": source_ip,
            "dest_ip": dest_ip,
            "protocol": protocol,
            "source_port": source_port,
            "dest_port": dest_port,
            "interface_in": in_match.group("in") if in_match else None,
            "interface_out": out_match.group("out") if out_match else None,
            "is_blocked": is_blocked,
            "details": f"{action} {protocol} {source_ip}:{source_port} -> {dest_ip}:{dest_port}"
        }
        events.append(event)

    return events
