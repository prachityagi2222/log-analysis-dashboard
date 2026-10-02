import math
from collections import Counter
from datetime import datetime
from typing import List, Dict, Any
import numpy as np
from sklearn.ensemble import IsolationForest
from dateutil import parser as date_parser
from app.detection.mitre import MITRE_TACTICS


class MLEngine:
    def __init__(self, contamination: float = 0.08):
        self.contamination = contamination

    def extract_features(self, events: List[Dict[str, Any]]) -> np.ndarray:
        if not events:
            return np.empty((0, 6))

        # Calculate IP frequencies across the log
        ip_counts = Counter(ev.get("source_ip") or "unknown" for ev in events)

        features = []
        for ev in events:
            # 1. Hour of day (0-23)
            hour = 12
            ts_str = ev.get("timestamp")
            if ts_str:
                try:
                    dt = date_parser.parse(ts_str)
                    hour = dt.hour
                except Exception:
                    pass

            # 2. Failure indicator (1 or 0)
            is_failure = 1.0 if ev.get("status") in ("failure", "error") or ev.get("is_blocked") else 0.0

            # 3. Privileged target (root/admin/etc)
            user_str = str(ev.get("user") or "").lower()
            url_str = str(ev.get("url") or "").lower()
            is_priv = 1.0 if ("root" in user_str or "admin" in user_str or "admin" in url_str) else 0.0

            # 4. Payload / message length
            raw_len = float(len(ev.get("raw", "")))

            # 5. Suspicious character density (quotes, slashes, semicolons, encoded chars)
            raw = ev.get("raw", "")
            special_count = sum(1 for c in raw if c in ("'", '"', ';', '|', '%', '<', '>', '`', '$'))
            char_density = float(special_count) / max(raw_len, 1.0)

            # 6. Source IP frequency (log scale)
            ip = ev.get("source_ip") or "unknown"
            ip_freq = float(ip_counts[ip])
            log_ip_freq = math.log1p(ip_freq)

            features.append([
                hour,
                is_failure,
                is_priv,
                raw_len,
                char_density,
                log_ip_freq
            ])

        return np.array(features, dtype=float)

    def run(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        detections = []
        if not events or len(events) < 5:
            # Need a minimum sample size for meaningful statistical anomaly detection
            return detections

        X = self.extract_features(events)
        if X.shape[0] < 5:
            return detections

        try:
            # Contamination rate: between 0.02 and 0.15 depending on volume
            effective_contamination = min(max(self.contamination, 0.02), 0.15)
            clf = IsolationForest(
                n_estimators=100,
                contamination=effective_contamination,
                random_state=42
            )
            preds = clf.fit_predict(X)  # -1 for anomaly, 1 for inlier
            scores = clf.decision_function(X)  # lower score = more anomalous

            anomaly_indices = [i for i, p in enumerate(preds) if p == -1]

            if anomaly_indices:
                # Calculate mean anomaly score of flagged items
                avg_score = float(np.mean([scores[i] for i in anomaly_indices]))
                # Determine severity: very negative score = higher severity
                severity = "high" if avg_score < -0.15 else "medium"

                # Extract notable features of the anomalies for the description
                anom_events = [events[i] for i in anomaly_indices]
                failed_count = sum(1 for e in anom_events if e.get("status") in ("failure", "error") or e.get("is_blocked"))
                distinct_ips = len(set(e.get("source_ip") for e in anom_events if e.get("source_ip")))

                desc = (
                    f"Isolation Forest ML detected {len(anomaly_indices)} statistical outliers "
                    f"exhibiting atypical timing, payload length, or access frequency across {distinct_ips} IP(s)."
                )

                detections.append({
                    "method": "ml",
                    "name": "ml_outlier_activity",
                    "severity": severity,
                    "description": desc,
                    "mitre_tactic": MITRE_TACTICS["DEFENSE_EVASION"],
                    "indices": anomaly_indices
                })
        except Exception as e:
            # ML detection should degrade gracefully without halting the pipeline
            pass

        return detections
