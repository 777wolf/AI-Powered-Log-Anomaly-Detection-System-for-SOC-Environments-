# scripts/splunk_forwarder.py
# Purpose: Forward high-confidence anomaly alerts to Splunk via HEC

import requests
import pandas as pd
import json
import os
import sys
import urllib3
from datetime import datetime

# Suppress SSL warnings (HEC running without SSL)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import DATA_PATH, SPLUNK_HOST, SPLUNK_PORT, SPLUNK_TOKEN


def send_to_splunk(event_data, severity="HIGH"):
    """
    Send a single event to Splunk HEC.

    HEC expects JSON in this format:
    {
        "event": { ...your data... },
        "sourcetype": "anomaly_detection",
        "source": "ai_log_anomaly_detector",
        "index": "main"
    }

    The Authorization header carries the HEC token.
    """
    url = f"http://{SPLUNK_HOST}:{SPLUNK_PORT}/services/collector/event"

    headers = {
        "Authorization": f"Splunk {SPLUNK_TOKEN}",
        "Content-Type": "application/json"
    }

    payload = {
        "event": event_data,
        "sourcetype": "anomaly_detection",
        "source": "ai_log_anomaly_detector",
        "index": "main"
    }

    try:
        response = requests.post(
            url,
            headers=headers,
            data=json.dumps(payload),
            verify=False,
            timeout=10
        )

        if response.status_code == 200:
            result = response.json()
            if result.get("code") == 0:
                return True
            else:
                print(f"    [!] HEC error: {result}")
                return False
        else:
            print(f"    [!] HTTP error: {response.status_code} - {response.text}")
            return False

    except requests.exceptions.ConnectionError:
        print(f"    [!] Cannot connect to Splunk at {SPLUNK_HOST}:{SPLUNK_PORT}")
        return False
    except Exception as e:
        print(f"    [!] Error: {e}")
        return False


def forward_anomalies(min_confidence="MEDIUM"):
    """
    Load anomaly results and forward all anomalies
    above the minimum confidence threshold to Splunk.

    min_confidence: "HIGH" = only high alerts
                    "MEDIUM" = high + medium alerts
    """
    path = os.path.join(DATA_PATH, "anomaly_results_tuned.csv")
    df = pd.read_csv(path)
    df['time_window'] = pd.to_datetime(df['time_window'])

    # Filter by confidence
    if min_confidence == "HIGH":
        alerts = df[df['confidence'] == 'HIGH']
    else:
        alerts = df[df['confidence'] != 'NORMAL']

    alerts = alerts.sort_values('combined_score', ascending=False)

    print("=" * 60)
    print("  Splunk HEC Forwarder")
    print("=" * 60)
    print(f"\n[*] Splunk target : {SPLUNK_HOST}:{SPLUNK_PORT}")
    print(f"[*] Min confidence: {min_confidence}")
    print(f"[*] Alerts to send: {len(alerts)}")
    print(f"\n[*] Forwarding alerts to Splunk...")
    print("-" * 60)

    sent     = 0
    failed   = 0
    forwarded_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for _, row in alerts.iterrows():

        # Build event payload
        event = {
            # Alert metadata
            "alert_time"          : forwarded_at,
            "detection_system"    : "AI-Powered Log Anomaly Detection",

            # Time window info
            "time_window"         : str(row['time_window']),

            # Confidence and scoring
            "confidence"          : str(row['confidence']),
            "combined_score"      : round(float(row['combined_score']), 4),
            "if_score"            : round(float(row['if_score']), 4),
            "lof_score"           : round(float(row['lof_score']), 4),

            # Model verdicts
            "isolation_forest"    : "ANOMALY" if row['if_label'] == -1 else "NORMAL",
            "local_outlier_factor": "ANOMALY" if row['lof_label'] == -1 else "NORMAL",
            "models_flagged"      : int(row['models_flagged']),

            # Security features
            "failed_logins"       : round(float(row['failed_logins']), 4),
            "success_logins"      : round(float(row['success_logins']), 4),
            "login_success_ratio" : round(float(row['login_success_ratio']), 4),
            "process_events"      : round(float(row['process_events']), 4),
            "priv_events"         : round(float(row['priv_events']), 4),
            "total_events"        : round(float(row['total_events']), 4),

            # Time context
            "hour_of_day"         : int(row['hour_of_day']),
            "is_night"            : int(row['is_night']),
            "is_weekend"          : int(row['is_weekend']),

            # Severity mapping for Splunk
            "severity"            : "critical" if row['confidence'] == 'HIGH' else "warning",
            "source_ip"           : "192.168.50.20",  # Windows 10 VM
            "attacker_ip"         : "192.168.50.10",  # Kali VM
        }

        # Send to Splunk
        success = send_to_splunk(event, severity=row['confidence'])

        if success:
            sent += 1
            badge = "[HIGH]  " if row['confidence'] == 'HIGH' else "[MEDIUM]"
            print(f"  {badge} {row['time_window']} | score: {row['combined_score']:.3f} -> Splunk OK")
        else:
            failed += 1
            print(f"  [FAIL]  {row['time_window']} -> Send failed")

    print("-" * 60)
    print(f"\n[+] Successfully forwarded : {sent} alerts")
    print(f"[!] Failed                 : {failed} alerts")
    print(f"\n[*] Check Splunk Search:")
    print(f"    http://{SPLUNK_HOST}:8000")
    print(f"    Search: sourcetype=anomaly_detection")


def test_connection():
    """Quick test to verify HEC is reachable before forwarding."""
    print("[*] Testing Splunk HEC connection...")

    test_event = {
        "test"      : True,
        "message"   : "HEC connection test from AI Anomaly Detector",
        "timestamp" : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source"    : "ai_log_anomaly_detector"
    }

    success = send_to_splunk(test_event)
    if success:
        print("[+] Connection successful! HEC is reachable.")
        return True
    else:
        print("[!] Connection failed. Check Splunk HEC settings.")
        return False


if __name__ == "__main__":

    # Step 1: Test connection
    if not test_connection():
        sys.exit(1)

    print()

    # Step 2: Forward all HIGH + MEDIUM alerts
    forward_anomalies(min_confidence="MEDIUM")