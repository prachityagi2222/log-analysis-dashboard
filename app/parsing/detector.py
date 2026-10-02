import re
from typing import List


def detect_log_type(lines: List[str]) -> str:
    """
    Analyzes sample log lines and returns 'ssh', 'web', 'firewall', or 'unknown'.
    """
    if not lines:
        return "unknown"

    sample = lines[:100]
    scores = {"ssh": 0, "web": 0, "firewall": 0}

    ssh_patterns = [
        re.compile(r"sshd(?:\[\d+\])?:", re.IGNORECASE),
        re.compile(r"Failed password for", re.IGNORECASE),
        re.compile(r"Accepted (?:password|publickey) for", re.IGNORECASE),
        re.compile(r"Invalid user", re.IGNORECASE),
        re.compile(r"pam_unix\(sshd", re.IGNORECASE),
        re.compile(r"Received disconnect from", re.IGNORECASE),
        re.compile(r"Connection closed by authenticating user", re.IGNORECASE),
    ]

    web_patterns = [
        re.compile(r'"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+.*?\s+HTTP/\d\.\d"', re.IGNORECASE),
        re.compile(r'^\S+ \S+ \S+ \[[^\]]+\] "(?:GET|POST|PUT|DELETE|HEAD)', re.IGNORECASE),
        re.compile(r'\s(?:200|301|302|400|401|403|404|500|502|503)\s+\d+'),
    ]

    firewall_patterns = [
        re.compile(r'\[UFW (?:BLOCK|ALLOW|AUDIT)\]', re.IGNORECASE),
        re.compile(r'\b(?:DROP|REJECT|ACCEPT|BLOCK)\b.*SRC=\S+ DST=\S+', re.IGNORECASE),
        re.compile(r'SRC=\d+\.\d+\.\d+\.\d+.*DST=\d+\.\d+\.\d+\.\d+.*PROTO=(?:TCP|UDP|ICMP)', re.IGNORECASE),
        re.compile(r'iptables:', re.IGNORECASE),
        re.compile(r'kernel:\s*\[\s*\d+\.\d+\].*PROTO=', re.IGNORECASE),
    ]

    for line in sample:
        line_clean = line.strip()
        if not line_clean:
            continue

        for p in ssh_patterns:
            if p.search(line_clean):
                scores["ssh"] += 1
                break

        for p in web_patterns:
            if p.search(line_clean):
                scores["web"] += 1
                break

        for p in firewall_patterns:
            if p.search(line_clean):
                scores["firewall"] += 1
                break

    best_type, max_score = max(scores.items(), key=lambda item: item[1])
    if max_score > 0:
        return best_type

    # Fallback heuristic
    full_sample_text = "\n".join(sample)
    if "sshd" in full_sample_text.lower() or "password" in full_sample_text.lower():
        return "ssh"
    if "http" in full_sample_text.lower() or "get " in full_sample_text.lower() or "post " in full_sample_text.lower():
        return "web"
    if "proto=" in full_sample_text.lower() or "src=" in full_sample_text.lower():
        return "firewall"

    return "ssh"  # Default fallback if indeterminate
