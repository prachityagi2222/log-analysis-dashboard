import os
import sys
from pathlib import Path
from fastapi.testclient import TestClient

# Ensure root directory is on Python path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.main import app

client = TestClient(app)


def test_health_and_ui():
    print("\n[+] Testing Root Endpoint and Static UI...")
    res = client.get("/")
    assert res.status_code == 200, f"Expected 200, got {res.status_code}"
    assert "Log Analysis Dashboard" in res.text, "Index HTML missing expected title"
    print("    [OK] Root endpoint and UI served successfully.")


def test_sample_files():
    print("\n[+] Testing Sample File Endpoints...")
    for sample in ["ssh_brute_force.log", "web_attacks.log", "firewall_port_scan.log"]:
        res = client.get(f"/sample/{sample}")
        assert res.status_code == 200, f"Failed to retrieve sample {sample}: {res.status_code}"
        assert len(res.text) > 0, f"Sample {sample} was empty"
        print(f"    [OK] Sample {sample} retrieved ({len(res.text)} bytes)")


def test_ssh_pipeline():
    print("\n[+] Testing SSH Pipeline (Upload -> Parse -> Rule -> ML -> Report)...")
    sample_path = Path("sample_logs") / "ssh_brute_force.log"
    with open(sample_path, "rb") as f:
        res = client.post(
            "/api/upload",
            files={"file": ("ssh_brute_force.log", f, "text/plain")}
        )
    assert res.status_code == 200, f"Upload failed: {res.text}"
    data = res.json()
    assert data["log_type"] == "ssh", f"Expected log_type=ssh, got {data['log_type']}"
    assert data["total_events"] > 0, "No events parsed"
    assert len(data["detections"]) > 0, "No detections returned"
    
    # Check brute force detection
    detection_names = [d["name"] for d in data["detections"]]
    assert "brute_force" in detection_names, f"Expected 'brute_force' in detections: {detection_names}"
    
    # Check report
    report = data["report"]
    assert report["severity"] in ("high", "critical"), f"Expected high/critical severity, got {report['severity']}"
    assert len(report["summary"]) > 20, "Summary paragraph too short or missing"
    assert "Credential Access" in report["tactics"], "Expected 'Credential Access' MITRE tactic"
    print(f"    [OK] SSH analysis complete: {len(data['detections'])} detections, Severity={report['severity']}, Mode={report['mode']}")

    return data["detections"][0]["id"], data["parsed_file_id"], data["log_file_id"]


def test_web_pipeline():
    print("\n[+] Testing Web Pipeline (Upload -> Parse -> Rule -> ML -> Report)...")
    sample_path = Path("sample_logs") / "web_attacks.log"
    with open(sample_path, "rb") as f:
        res = client.post(
            "/api/upload",
            files={"file": ("web_attacks.log", f, "text/plain")}
        )
    assert res.status_code == 200, f"Upload failed: {res.text}"
    data = res.json()
    assert data["log_type"] == "web", f"Expected log_type=web, got {data['log_type']}"
    det_names = [d["name"] for d in data["detections"]]
    assert any("sql" in name for name in det_names), f"Expected SQL injection detection in {det_names}"
    print(f"    [OK] Web analysis complete: {len(data['detections'])} detections, Overall Severity={data['report']['severity']}")


def test_firewall_pipeline():
    print("\n[+] Testing Firewall Pipeline (Upload -> Parse -> Rule -> ML -> Report)...")
    sample_path = Path("sample_logs") / "firewall_port_scan.log"
    with open(sample_path, "rb") as f:
        res = client.post(
            "/api/upload",
            files={"file": ("firewall_port_scan.log", f, "text/plain")}
        )
    assert res.status_code == 200, f"Upload failed: {res.text}"
    data = res.json()
    assert data["log_type"] == "firewall", f"Expected log_type=firewall, got {data['log_type']}"
    det_names = [d["name"] for d in data["detections"]]
    assert "port_scan" in det_names, f"Expected port_scan detection in {det_names}"
    print(f"    [OK] Firewall analysis complete: {len(data['detections'])} detections, Tactics={data['report']['tactics']}")


def test_detection_detail_and_report(detection_id, parsed_file_id, log_file_id):
    print("\n[+] Testing Screen 3 & Screen 4 APIs...")
    # Screen 3: Detection Detail
    det_res = client.get(f"/api/detection/{detection_id}/detail")
    assert det_res.status_code == 200, f"Failed getting detection detail: {det_res.text}"
    det_data = det_res.json()
    assert len(det_data["raw_lines"]) > 0, "No raw lines returned for detection"
    assert len(det_data["matched_events"]) > 0, "No matched events returned for detection"
    print(f"    [OK] Screen 3 Detail API returned {len(det_data['raw_lines'])} raw log lines matching detection.")

    # Screen 4: Full Report
    rep_res = client.get(f"/api/report/{parsed_file_id}")
    assert rep_res.status_code == 200, f"Failed getting report: {rep_res.text}"
    rep_data = rep_res.json()
    assert len(rep_data["summary"]) > 0, "Report summary was empty"
    print(f"    [OK] Screen 4 Report API returned report #{rep_data['id']}.")

    # Screen 1: Recent logs listing
    list_res = client.get("/api/logs")
    assert list_res.status_code == 200, f"Failed listing logs: {list_res.text}"
    logs = list_res.json()
    assert len(logs) >= 3, f"Expected at least 3 logs in history, got {len(logs)}"
    print(f"    [OK] Screen 1 Recent Logs API returned {len(logs)} uploaded logs.")


if __name__ == "__main__":
    print("=" * 60)
    print("RUNNING LOG ANALYSIS DASHBOARD MVP TEST SUITE")
    print("=" * 60)
    test_health_and_ui()
    test_sample_files()
    det_id, parsed_id, log_id = test_ssh_pipeline()
    test_web_pipeline()
    test_firewall_pipeline()
    test_detection_detail_and_report(det_id, parsed_id, log_id)
    print("\n" + "=" * 60)
    print("ALL TESTS PASSED SUCCESSFULLY! SERVER AND PIPELINE ARE FULLY FUNCTIONAL.")
    print("=" * 60)
