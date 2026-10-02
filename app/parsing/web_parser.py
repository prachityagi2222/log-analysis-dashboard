import re
from datetime import datetime
from typing import List, Dict, Any, Optional
from dateutil import parser as date_parser


def parse_web_timestamp(ts_str: str) -> Optional[str]:
    try:
        # Format usually: 10/Oct/2000:13:55:36 -0700 or Oct 10 13:55:36
        cleaned = ts_str.strip("[]")
        # Replace first colon after day/month/year with space if present
        # e.g., 02/Oct/2026:14:32:10 -> 02/Oct/2026 14:32:10
        m = re.match(r"^(\d{1,2}/\w{3}/\d{4}):(\d{2}:\d{2}:\d{2}\s*[+-]?\d{0,4})", cleaned)
        if m:
            cleaned = f"{m.group(1)} {m.group(2)}"
        dt = date_parser.parse(cleaned)
        return dt.isoformat()
    except Exception:
        return None


def parse_web_lines(lines: List[str]) -> List[Dict[str, Any]]:
    events = []

    # Combined Log Format: 127.0.0.1 - user [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://..." "Mozilla/..."
    combined_re = re.compile(
        r'^(?P<ip>\S+)\s+(?P<ident>\S+)\s+(?P<user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<request>[^"]*)"\s+(?P<status>\d{3})\s+(?P<bytes>\S+)(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
    )

    request_re = re.compile(r'^(?P<method>[A-Z]+)\s+(?P<url>\S+)(?:\s+(?P<protocol>HTTP/\d\.\d))?', re.IGNORECASE)

    for idx, raw_line in enumerate(lines):
        line = raw_line.strip()
        if not line:
            continue

        m = combined_re.match(line)
        if m:
            ip = m.group("ip")
            user = m.group("user") if m.group("user") != "-" else None
            ts_str = m.group("timestamp")
            request_str = m.group("request")
            status_code = int(m.group("status"))
            bytes_str = m.group("bytes")
            resp_bytes = int(bytes_str) if bytes_str.isdigit() else 0
            referer = m.group("referer") if m.group("referer") != "-" else None
            user_agent = m.group("user_agent") if m.group("user_agent") != "-" else None

            method = "GET"
            url = "/"
            protocol = "HTTP/1.1"

            m_req = request_re.match(request_str)
            if m_req:
                method = m_req.group("method")
                url = m_req.group("url")
                if m_req.group("protocol"):
                    protocol = m_req.group("protocol")

            event = {
                "index": idx,
                "raw": line,
                "timestamp": parse_web_timestamp(ts_str) or datetime.utcnow().isoformat(),
                "service": "web",
                "source_ip": ip,
                "user": user,
                "method": method,
                "url": url,
                "protocol": protocol,
                "status_code": status_code,
                "status": "failure" if status_code >= 400 else "success",
                "bytes": resp_bytes,
                "referer": referer,
                "user_agent": user_agent,
                "action": f"{method} {url}",
                "details": f"{method} {url} -> {status_code}"
            }
            events.append(event)
        else:
            # Fallback for non-standard web logs
            status_match = re.search(r'\s(?P<status>[1-5]\d{2})\s', line)
            status_code = int(status_match.group("status")) if status_match else 200
            ip_match = re.search(r'\b(?P<ip>\d+\.\d+\.\d+\.\d+)\b', line)
            req_match = re.search(r'"(?P<method>[A-Z]+)\s+(?P<url>\S+)', line)

            event = {
                "index": idx,
                "raw": line,
                "timestamp": datetime.utcnow().isoformat(),
                "service": "web",
                "source_ip": ip_match.group("ip") if ip_match else "unknown",
                "user": None,
                "method": req_match.group("method") if req_match else "GET",
                "url": req_match.group("url") if req_match else "/",
                "protocol": "HTTP/1.1",
                "status_code": status_code,
                "status": "failure" if status_code >= 400 else "success",
                "bytes": 0,
                "referer": None,
                "user_agent": None,
                "action": line[:60],
                "details": line
            }
            events.append(event)

    return events
