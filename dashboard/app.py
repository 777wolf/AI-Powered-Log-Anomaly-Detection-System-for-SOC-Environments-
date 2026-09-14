# dashboard/app.py
# Full featured SOC Anomaly Detection Dashboard Backend

from flask import Flask, render_template, jsonify, request, send_file
import pandas as pd
import json
import os
import sys
import subprocess
import threading
import time
import io
import csv
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import DATA_PATH, MODEL_PATH, RANDOM_STATE, CONTAMINATION
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

app = Flask(__name__)

# Global status trackers
job_status = {
    "collect"  : {"running": False, "message": "Idle", "done": False},
    "retrain"  : {"running": False, "message": "Idle", "done": False},
    "attack"   : {"running": False, "message": "Idle", "done": False},
}

KNOWN_ATTACKS = [
    '2026-03-01 17:10:00', '2026-03-01 17:19:00',
    '2026-03-01 17:20:00', '2026-03-01 17:21:00',
    '2026-03-01 17:22:00', '2026-03-02 13:19:00',
    '2026-04-16 08:24:00', '2026-04-16 08:25:00',
    '2026-04-16 08:28:00', '2026-04-16 08:36:00',
    '2026-04-16 08:37:00', '2026-04-16 08:38:00',
    '2026-04-18 11:31:00', '2026-04-18 11:55:00',
    '2026-04-18 11:56:00',
]


def load_data():
    path = os.path.join(DATA_PATH, "anomaly_results_tuned.csv")
    df = pd.read_csv(path)
    df['time_window'] = pd.to_datetime(df['time_window'])
    df = df.sort_values('time_window').reset_index(drop=True)
    return df


# ── MAIN PAGE ──
@app.route('/')
def index():
    return render_template('index.html')


# ── SUMMARY STATS ──
@app.route('/api/summary')
def summary():
    df = load_data()
    high   = len(df[df['confidence'] == 'HIGH'])
    medium = len(df[df['confidence'] == 'MEDIUM'])
    normal = len(df[df['confidence'] == 'NORMAL'])
    total  = len(df)

    # Detection rate = anomalies detected out of total windows
    detected = high + medium
    rate = round(detected / total * 100, 1) if total > 0 else 0

    return jsonify({
        'high'          : high,
        'medium'        : medium,
        'normal'        : normal,
        'total'         : total,
        'attack_windows': total,
        'detected'      : detected,
        'detection_rate': rate,
        'last_updated'  : datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })


# ── TIMELINE DATA ──
@app.route('/api/timeline')
def timeline():
    df = load_data()
    data = []
    for _, row in df.iterrows():
        data.append({
            'time'          : str(row['time_window']),
            'failed_logins' : round(float(row['failed_logins']), 4),
            'combined_score': round(float(row['combined_score']), 4),
            'confidence'    : str(row['confidence']),
            'process_events': round(float(row['process_events']), 4),
            'priv_events'   : round(float(row['priv_events']), 4),
            'total_events'  : round(float(row['total_events']), 4),
        })
    return jsonify(data)

# ── LOGIN_TIMELINE TABLE ──
@app.route('/api/login_timeline')
def login_timeline():
    """Returns actual raw event counts from raw_logs.csv."""
    raw_path = os.path.join(DATA_PATH, "raw_logs.csv")
    if not os.path.exists(raw_path):
        return jsonify([])

    df = pd.read_csv(raw_path)

    def parse_ts(ts):
        try:
            return pd.to_datetime(str(ts).split('.')[0], format='%Y%m%d%H%M%S')
        except:
            return pd.NaT

    df['timestamp'] = df['timestamp'].apply(parse_ts)
    df = df.dropna(subset=['timestamp'])
    df['hour'] = df['timestamp'].dt.floor('h')

    failed  = df[df['event_id'] == 4625].groupby('hour').size().reset_index(name='failed')
    success = df[df['event_id'] == 4624].groupby('hour').size().reset_index(name='success')

    hourly = pd.merge(failed, success, on='hour', how='outer').fillna(0).sort_values('hour')

    return jsonify([{
        'hour'   : str(row['hour']),
        'failed' : int(row['failed']),
        'success': int(row['success']),
    } for _, row in hourly.iterrows()])

# ── ALERTS TABLE ──
@app.route('/api/alerts')
def alerts():
    df = load_data()
    anomalies = df[df['confidence'] != 'NORMAL'].copy()
    anomalies = anomalies.sort_values('combined_score', ascending=False)
    result = []
    for _, row in anomalies.iterrows():
        result.append({
            'time'               : str(row['time_window']),
            'confidence'         : str(row['confidence']),
            'failed_logins'      : round(float(row['failed_logins']), 4),
            'login_success_ratio': round(float(row['login_success_ratio']), 4),
            'process_events'     : round(float(row['process_events']), 4),
            'priv_events'        : round(float(row['priv_events']), 4),
            'total_events'       : round(float(row['total_events']), 4),
            'combined_score'     : round(float(row['combined_score']), 4),
            'if_score'           : round(float(row['if_score']), 4),
            'lof_score'          : round(float(row['lof_score']), 4),
            'if_label'           : int(row['if_label']),
            'lof_label'          : int(row['lof_label']),
            'models_flagged'     : int(row['models_flagged']),
            'hour_of_day'        : int(row['hour_of_day']),
            'is_night'           : int(row['is_night']),
            'is_weekend'         : int(row['is_weekend']),
        })
    return jsonify(result)


# ── ALERT DETAIL (for popup) ──
@app.route('/api/alert/<path:time_window>')
def alert_detail(time_window):
    df = load_data()
    row = df[df['time_window'].astype(str) == time_window]
    if row.empty:
        return jsonify({'error': 'Not found'}), 404
    row = row.iloc[0]
    return jsonify({
        'time'               : str(row['time_window']),
        'confidence'         : str(row['confidence']),
        'combined_score'     : round(float(row['combined_score']), 4),
        'if_score'           : round(float(row['if_score']), 4),
        'lof_score'          : round(float(row['lof_score']), 4),
        'if_label'           : int(row['if_label']),
        'lof_label'          : int(row['lof_label']),
        'models_flagged'     : int(row['models_flagged']),
        'failed_logins'      : round(float(row['failed_logins']), 4),
        'success_logins'     : round(float(row['success_logins']), 4),
        'login_success_ratio': round(float(row['login_success_ratio']), 4),
        'process_events'     : round(float(row['process_events']), 4),
        'priv_events'        : round(float(row['priv_events']), 4),
        'total_events'       : round(float(row['total_events']), 4),
        'logoffs'            : round(float(row['logoffs']), 4),
        'hour_of_day'        : int(row['hour_of_day']),
        'is_night'           : int(row['is_night']),
        'is_weekend'         : int(row['is_weekend']),
        'attacker_ip'        : '192.168.50.10',
        'victim_ip'          : '192.168.50.20',
        'mitre_technique'    : 'T1110 - Brute Force' if float(row['failed_logins']) > 0 else 'T1059 - Command Execution',
        'recommended_action' : 'Block source IP, reset affected credentials, review process creation logs' if row['confidence'] == 'HIGH' else 'Monitor for continued activity',
    })


# ── LIVE LOG COLLECTION ──
def run_collection():
    job_status["collect"]["running"] = True
    job_status["collect"]["done"]    = False
    job_status["collect"]["message"] = "Connecting to Windows 10 VM..."
    try:
        job_status["collect"]["message"] = "Collecting logs via WMI (takes 1-3 mins)..."
        result = subprocess.run(
            [sys.executable,
             os.path.join(BASE_DIR, "scripts", "log_collector.py"),
             "tks", "12345678"],
            capture_output=True, text=True, timeout=300, cwd=BASE_DIR
        )
        if result.returncode != 0:
            job_status["collect"]["message"] = f"Collection failed: {result.stderr[:200]}"
            return
        lines      = result.stdout.strip().split('\n')
        shape_line = next((l for l in lines if 'Shape' in l), "Logs collected")
        job_status["collect"]["message"] = f"{shape_line}. Running feature engineering..."

        result2 = subprocess.run(
            [sys.executable,
             os.path.join(BASE_DIR, "scripts", "feature_engineering.py")],
            capture_output=True, text=True, timeout=90, cwd=BASE_DIR
        )
        if result2.returncode != 0:
            job_status["collect"]["message"] = f"Feature engineering failed: {result2.stderr[:200]}"
            return
        fe_lines     = result2.stdout.strip().split('\n')
        windows_line = next((l for l in fe_lines if 'time windows' in l), "Features ready")
        job_status["collect"]["message"] = f"Done! {windows_line}. Now click Retrain Models."
        job_status["collect"]["done"] = True
    except subprocess.TimeoutExpired:
        job_status["collect"]["message"] = "Timed out after 5 minutes. Check if Windows VM is on."
    except Exception as e:
        job_status["collect"]["message"] = f"Error: {str(e)[:200]}"
    finally:
        job_status["collect"]["running"] = False


# ── ML MODEL RETRAINING ──
def run_retrain():
    job_status["retrain"]["running"] = True
    job_status["retrain"]["done"]    = False
    job_status["retrain"]["message"] = "Running Isolation Forest + LOF..."
    try:
        r1 = subprocess.run(
            [sys.executable,
             os.path.join(BASE_DIR, "scripts", "anomaly_detection.py")],
            capture_output=True, text=True, timeout=120, cwd=BASE_DIR
        )
        if r1.returncode != 0:
            job_status["retrain"]["message"] = f"Detection failed: {r1.stderr[:150]}"
            return
        job_status["retrain"]["message"] = "Tuning hyperparameters..."
        r2 = subprocess.run(
            [sys.executable,
             os.path.join(BASE_DIR, "scripts", "tune_model.py")],
            capture_output=True, text=True, timeout=180, cwd=BASE_DIR
        )
        if r2.returncode != 0:
            job_status["retrain"]["message"] = f"Tuning failed: {r2.stderr[:150]}"
            return
        lines     = r2.stdout.strip().split('\n')
        rate_line = next((l for l in lines if 'Detection Rate' in l), "")
        job_status["retrain"]["message"] = f"Done! {rate_line.strip()}. Dashboard updated."
        job_status["retrain"]["done"] = True
    except subprocess.TimeoutExpired:
        job_status["retrain"]["message"] = "Timed out during retraining."
    except Exception as e:
        job_status["retrain"]["message"] = f"Error: {str(e)[:150]}"
    finally:
        job_status["retrain"]["running"] = False

# ── SYSTEM STATUS ──
@app.route('/api/status')
def system_status():
    import socket

    def ping(host, port, timeout=2):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except:
            return False

    # Check Windows 10 VM
    vm_online     = ping("192.168.56.102", 3389)  # RDP port

    # Check Splunk Web
    splunk_web    = ping("192.168.56.101", 8000)

    # Check Splunk HEC
    splunk_hec    = ping("192.168.56.101", 8088)

    # Check data freshness
    raw_path      = os.path.join(DATA_PATH, "raw_logs.csv")
    results_path  = os.path.join(DATA_PATH, "anomaly_results_tuned.csv")

    raw_fresh     = os.path.exists(raw_path)
    results_fresh = os.path.exists(results_path)

    raw_time      = ""
    results_time  = ""

    if raw_fresh:
        ts       = os.path.getmtime(raw_path)
        raw_time = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")

    if results_fresh:
        ts           = os.path.getmtime(results_path)
        results_time = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")

    return jsonify({
        "vm_online"    : vm_online,
        "splunk_web"   : splunk_web,
        "splunk_hec"   : splunk_hec,
        "raw_logs"     : raw_fresh,
        "raw_time"     : raw_time,
        "model_ready"  : results_fresh,
        "results_time" : results_time,
    })


# ── EVENT ID BREAKDOWN ──
@app.route('/api/event_breakdown')
def event_breakdown():
    raw_path = os.path.join(DATA_PATH, "raw_logs.csv")
    if not os.path.exists(raw_path):
        return jsonify([])

    df     = pd.read_csv(raw_path)
    counts = df['event_id'].value_counts().reset_index()
    counts.columns = ['event_id', 'count']

    event_names = {
        4624: "Successful Login",
        4625: "Failed Login",
        4634: "Logoff",
        4672: "Privilege Assigned",
        4688: "Process Created",
        4698: "Scheduled Task",
        4720: "New User Created",
    }

    result = []
    for _, row in counts.iterrows():
        eid = int(row['event_id'])
        result.append({
            'event_id'  : eid,
            'name'      : event_names.get(eid, f"Event {eid}"),
            'count'     : int(row['count']),
            'label'     : f"{eid} - {event_names.get(eid, 'Unknown')}",
        })
    return jsonify(result)

# ── ATTACK SIMULATION ──
def run_attack(attack_type, target_ip, username):
    job_status["attack"]["running"] = True
    job_status["attack"]["done"]    = False
    job_status["attack"]["message"] = f"Launching {attack_type} attack..."
    try:
        if attack_type == "hydra":
            job_status["attack"]["message"] = f"Running Hydra RDP brute force on {target_ip}..."
            result = subprocess.run([
                "ssh", "wolf@192.168.50.10",
                f"hydra -l {username} -P /usr/share/wordlists/rockyou.txt rdp://{target_ip} -t 4 -W 1 -f -e nsr"
            ], capture_output=True, text=True, timeout=120)
            job_status["attack"]["message"] = "Hydra attack complete. Re-collect logs to see new events."
        elif attack_type == "nmap":
            job_status["attack"]["message"] = f"Running Nmap scan on {target_ip}..."
            result = subprocess.run([
                "ssh", "wolf@192.168.50.10",
                f"nmap -sS -sV -p 1-1000 {target_ip} -e eth1"
            ], capture_output=True, text=True, timeout=120)
            job_status["attack"]["message"] = "Nmap scan complete. Re-collect logs to see new events."
        elif attack_type == "both":
            job_status["attack"]["message"] = "Running both attacks simultaneously..."
            subprocess.run([
                "ssh", "wolf@192.168.50.10",
                f"nmap -sS -p 1-1000 {target_ip} -e eth1 & hydra -l {username} -P /usr/share/wordlists/rockyou.txt rdp://{target_ip} -t 4 -W 1 -f"
            ], capture_output=True, text=True, timeout=120)
            job_status["attack"]["message"] = "Both attacks complete."
    except Exception as e:
        job_status["attack"]["message"] = f"Error: {str(e)[:100]}"
    finally:
        job_status["attack"]["running"] = False
        job_status["attack"]["done"]    = True

@app.route('/api/attack', methods=['POST'])
def trigger_attack():
    if job_status["attack"]["running"]:
        return jsonify({"status": "already_running"})
    data        = request.json
    attack_type = data.get("type", "hydra")
    target_ip   = data.get("target", "192.168.50.20")
    username    = data.get("username", "tks")
    t = threading.Thread(target=run_attack, args=(attack_type, target_ip, username))
    t.daemon = True
    t.start()
    return jsonify({"status": "started", "attack": attack_type, "target": target_ip})

@app.route('/api/attack/status')
def attack_status():
    return jsonify(job_status["attack"])


# ── EXPORT CSV ──
@app.route('/api/export/csv')
def export_csv():
    df = load_data()
    anomalies = df[df['confidence'] != 'NORMAL'].copy()
    anomalies = anomalies.sort_values('combined_score', ascending=False)

    output = io.StringIO()
    cols = ['time_window','confidence','combined_score','failed_logins',
            'login_success_ratio','process_events','if_label','lof_label','models_flagged']
    anomalies[cols].to_csv(output, index=False)
    output.seek(0)

    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'anomaly_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    )


# ── EXPORT PDF (simple HTML print) ──
@app.route('/api/export/pdf')
def export_pdf():
    return jsonify({"action": "print"})

@app.route('/api/collect', methods=['POST'])
def trigger_collect():
    if job_status["collect"]["running"]:
        return jsonify({"status": "already_running"})
    t = threading.Thread(target=run_collection)
    t.daemon = True
    t.start()
    return jsonify({"status": "started"})

@app.route('/api/collect/status')
def collect_status():
    return jsonify(job_status["collect"])

@app.route('/api/retrain', methods=['POST'])
def trigger_retrain():
    if job_status["retrain"]["running"]:
        return jsonify({"status": "already_running"})
    t = threading.Thread(target=run_retrain)
    t.daemon = True
    t.start()
    return jsonify({"status": "started"})

@app.route('/api/retrain/status')
def retrain_status():
    return jsonify(job_status["retrain"])

# ── SPLUNK FORWARDER ──
def run_splunk_forward():
    job_status["splunk"] = {"running": True, "message": "Connecting to Splunk...", "done": False}
    try:
        result = subprocess.run(
            [sys.executable, os.path.join(BASE_DIR, "scripts", "splunk_forwarder.py")],
            capture_output=True, text=True, timeout=120, cwd=BASE_DIR
        )
        if result.returncode != 0:
            job_status["splunk"]["message"] = f"Failed: {result.stderr[:200]}"
            return
        lines = result.stdout.strip().split('\n')
        sent_line = next((l for l in lines if 'Successfully forwarded' in l), "Forwarding complete")
        job_status["splunk"]["message"] = f"Done! {sent_line.strip()}"
        job_status["splunk"]["done"] = True
    except subprocess.TimeoutExpired:
        job_status["splunk"]["message"] = "Timed out. Check Splunk server is running."
    except Exception as e:
        job_status["splunk"]["message"] = f"Error: {str(e)[:200]}"
    finally:
        job_status["splunk"]["running"] = False


@app.route('/api/splunk', methods=['POST'])
def trigger_splunk():
    if job_status.get("splunk", {}).get("running"):
        return jsonify({"status": "already_running"})
    job_status["splunk"] = {"running": False, "message": "Idle", "done": False}
    t = threading.Thread(target=run_splunk_forward)
    t.daemon = True
    t.start()
    return jsonify({"status": "started"})


@app.route('/api/splunk/status')
def splunk_status():
    return jsonify(job_status.get("splunk", {"running": False, "message": "Idle", "done": False}))

@app.route('/print')
def print_view():
    return render_template('print.html')

if __name__ == '__main__':
    app.run(debug=True, port=5000)