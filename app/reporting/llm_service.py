import json
import logging
from typing import List, Dict, Any, Tuple
import requests
from app.config import OLLAMA_BASE_URL, OLLAMA_MODEL, OLLAMA_TIMEOUT

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0
}


def calculate_overall_severity(detections: List[Dict[str, Any]]) -> str:
    if not detections:
        return "low"
    max_sev = "low"
    max_val = 1
    for d in detections:
        sev = str(d.get("severity", "low")).lower()
        val = SEVERITY_ORDER.get(sev, 1)
        if val > max_val:
            max_val = val
            max_sev = sev
    return max_sev


def generate_mock_report(
    log_type: str,
    original_filename: str,
    total_events: int,
    detections: List[Dict[str, Any]]
) -> Tuple[str, str, List[str], str]:
    """
    Fallback deterministic generator producing rich plain-English security summaries.
    Returns: (summary, severity, tactics, mode="mock")
    """
    severity = calculate_overall_severity(detections)
    tactics = sorted(list(set(d.get("mitre_tactic") for d in detections if d.get("mitre_tactic"))))

    if not detections:
        summary = (
            f"The log file '{original_filename}' containing {total_events} {log_type.upper()} events was analyzed. "
            "No known attack signatures or significant behavioral anomalies were identified. "
            "System activities appear consistent with standard operational baselines."
        )
        return summary, "low", [], "mock"

    rule_detections = [d for d in detections if d.get("method") == "rule"]
    ml_detections = [d for d in detections if d.get("method") == "ml"]

    finding_summaries = []
    for d in rule_detections:
        finding_summaries.append(d.get("description"))

    ml_summary_parts = []
    if ml_detections:
        for md in ml_detections:
            ml_summary_parts.append(md.get("description"))

    severity_verb = {
        "critical": "critical security threats requiring immediate remediation",
        "high": "high-priority malicious activity",
        "medium": "suspicious events that warrant operational review",
        "low": "minor anomalous patterns of low risk"
    }.get(severity, "anomalous events")

    # Plain English narrative construction
    paragraph_parts = [
        f"Investigation of '{original_filename}' ({total_events} {log_type.upper()} events) uncovered {severity_verb}."
    ]

    if finding_summaries:
        lead_findings = "; ".join(finding_summaries[:3])
        paragraph_parts.append(f"Primary rule triggers indicate {lead_findings}.")

    if ml_summary_parts:
        paragraph_parts.append(ml_summary_parts[0])

    if severity in ("critical", "high"):
        paragraph_parts.append(
            "Immediate containment actions, including firewall IP blocking and credential rotation, are strongly recommended."
        )
    elif severity == "medium":
        paragraph_parts.append("Monitoring the identified source addresses and tightening access controls is advised.")
    else:
        paragraph_parts.append("Routine monitoring should be maintained.")

    summary = " ".join(paragraph_parts)
    return summary, severity, tactics, "mock"


def generate_llm_report(
    log_type: str,
    original_filename: str,
    total_events: int,
    detections: List[Dict[str, Any]]
) -> Tuple[str, str, List[str], str]:
    """
    Attempts to use local Ollama LLM for natural language summary.
    Falls back to generate_mock_report if Ollama is unavailable or fails.
    """
    severity = calculate_overall_severity(detections)
    tactics = sorted(list(set(d.get("mitre_tactic") for d in detections if d.get("mitre_tactic"))))

    # Test if Ollama is responsive
    prompt = (
        f"You are an expert security incident analyst. Provide a concise, executive-level security investigation report.\n"
        f"File: {original_filename}\n"
        f"Log Type: {log_type}\n"
        f"Total Events: {total_events}\n"
        f"Overall Severity: {severity}\n"
        f"MITRE Tactics: {', '.join(tactics) if tactics else 'None'}\n"
        f"Detections:\n"
    )
    for d in detections[:10]:
        prompt += f"- [{d.get('severity').upper()}] {d.get('name')}: {d.get('description')} ({d.get('mitre_tactic')})\n"

    prompt += (
        "\nIn one clear, professional paragraph (3-5 sentences), summarize what happened, "
        "what is suspicious, and how severe the situation is for the analyst."
    )

    try:
        response = requests.post(
            f"{OLLAMA_BASE_URL}/api/generate",
            json={
                "model": OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False
            },
            timeout=OLLAMA_TIMEOUT
        )
        if response.status_code == 200:
            data = response.json()
            llm_text = data.get("response", "").strip()
            if llm_text:
                return llm_text, severity, tactics, "real"
    except Exception as ex:
        logger.debug(f"Ollama not available or timed out: {ex}. Falling back to mock generator.")

    # Graceful fallback to deterministic mock mode
    return generate_mock_report(log_type, original_filename, total_events, detections)
