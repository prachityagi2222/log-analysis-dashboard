import re
from datetime import datetime
from typing import List, Dict, Any, Optional
from dateutil import parser as date_parser


def parse_timestamp(ts_str: str) -> Optional[str]:
    try:
        dt = date_parser.parse(ts_str)
        # If year was missing (e.g. 'Oct 02 12:34:56'), dateutil defaults to current year
        return dt.isoformat()
    except Exception:
        return None


def parse_ssh_lines(lines: List[str]) -> List[Dict[str, Any]]:
    events = []
    
    # Regex for standard syslog prefix: Month Day HH:MM:SS (optional hostname) sshd[PID]:
    syslog_prefix = re.compile(
        r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
        r"(?:(?P<host>\S+)\s+)?"
        r"(?:sshd(?:\[(?P<pid>\d+)\])?:\s+)?"
        r"(?P<message>.*)$",
        re.IGNORECASE
    )

    failed_re = re.compile(
        r"Failed\s+(?:password|publickey)\s+for\s+(?P<invalid>invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+)\s+port\s+(?P<port>\d+)",
        re.IGNORECASE
    )
    accepted_re = re.compile(
        r"Accepted\s+(?:password|publickey)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+)\s+port\s+(?P<port>\d+)",
        re.IGNORECASE
    )
    invalid_user_re = re.compile(
        r"Invalid\s+user\s+(?P<user>\S+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+)\s+port\s+(?P<port>\d+)",
        re.IGNORECASE
    )
    disconnect_re = re.compile(
        r"(?:Received\s+disconnect|Connection\s+closed)\s+from\s+(?:authenticating\s+user\s+(?P<user>\S+)\s+)?(?P<ip>\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+)\s+port\s+(?P<port>\d+)",
        re.IGNORECASE
    )
    generic_ip_re = re.compile(r"\b(?P<ip>\d+\.\d+\.\d+\.\d+)\b")

    for idx, raw_line in enumerate(lines):
        line = raw_line.strip()
        if not line:
            continue

        timestamp = None
        host = None
        message = line
        pid = None

        m_prefix = syslog_prefix.match(line)
        if m_prefix:
            ts_candidate = m_prefix.group("timestamp")
            timestamp = parse_timestamp(ts_candidate)
            host = m_prefix.group("host")
            pid = m_prefix.group("pid")
            message = m_prefix.group("message")

        event = {
            "index": idx,
            "raw": line,
            "timestamp": timestamp or datetime.utcnow().isoformat(),
            "service": "sshd",
            "host": host or "localhost",
            "pid": pid,
            "action": "unknown",
            "status": "info",
            "user": None,
            "source_ip": None,
            "source_port": None,
            "is_invalid_user": False,
            "is_root": False,
            "details": message
        }

        # Check failed login
        m_failed = failed_re.search(message)
        if m_failed:
            event["action"] = "failed_login"
            event["status"] = "failure"
            event["user"] = m_failed.group("user")
            event["source_ip"] = m_failed.group("ip")
            event["source_port"] = int(m_failed.group("port"))
            event["is_invalid_user"] = bool(m_failed.group("invalid"))
            event["is_root"] = (event["user"] == "root")
            events.append(event)
            continue

        # Check accepted login
        m_accepted = accepted_re.search(message)
        if m_accepted:
            event["action"] = "accepted_login"
            event["status"] = "success"
            event["user"] = m_accepted.group("user")
            event["source_ip"] = m_accepted.group("ip")
            event["source_port"] = int(m_accepted.group("port"))
            event["is_root"] = (event["user"] == "root")
            events.append(event)
            continue

        # Check invalid user
        m_invalid = invalid_user_re.search(message)
        if m_invalid:
            event["action"] = "invalid_user"
            event["status"] = "failure"
            event["user"] = m_invalid.group("user")
            event["source_ip"] = m_invalid.group("ip")
            event["source_port"] = int(m_invalid.group("port"))
            event["is_invalid_user"] = True
            event["is_root"] = (event["user"] == "root")
            events.append(event)
            continue

        # Check disconnect
        m_disc = disconnect_re.search(message)
        if m_disc:
            event["action"] = "disconnect"
            event["status"] = "info"
            event["user"] = m_disc.group("user")
            event["source_ip"] = m_disc.group("ip")
            event["source_port"] = int(m_disc.group("port")) if m_disc.group("port") else None
            events.append(event)
            continue

        # Fallback ip extraction
        m_ip = generic_ip_re.search(message)
        if m_ip:
            event["source_ip"] = m_ip.group("ip")

        if "failure" in message.lower() or "failed" in message.lower() or "error" in message.lower():
            event["status"] = "failure"
        elif "accepted" in message.lower() or "session opened" in message.lower():
            event["status"] = "success"

        events.append(event)

    return events
