import os
import sys
import subprocess


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run_stage(name, script):
    print("\n" + "=" * 60)
    print(f"  {name}")
    print("=" * 60)

    script_path = os.path.join(BASE_DIR, "scripts", script)

    result = subprocess.run(
        [sys.executable, script_path],
        cwd=BASE_DIR
    )

    if result.returncode != 0:
        print(f"\n[!] {name} failed.")
        print(f"[!] Pipeline stopped.")
        sys.exit(result.returncode)

    print(f"\n[+] {name} completed successfully.")


if __name__ == "__main__":

    print("=" * 60)
    print("  AI Log Anomaly Detection Pipeline")
    print("=" * 60)

    run_stage("Phase 2: Log Collection", "log_collector.py")
    run_stage("Phase 3: Feature Engineering", "feature_engineering.py")
    run_stage("Phase 4: Anomaly Detection", "anomaly_detection.py")
    run_stage("Phase 5: Splunk Forwarding", "splunk_forwarder.py")

    print("\n" + "=" * 60)
    print("  PIPELINE COMPLETED SUCCESSFULLY")
    print("=" * 60)