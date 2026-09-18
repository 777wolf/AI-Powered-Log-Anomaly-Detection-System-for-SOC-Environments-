# AI-Powered Log Anomaly Detection System for SOC Environments

**Machine Learning + Windows Security Logs + SOC Dashboard + Splunk SIEM**

An AI/ML-based security monitoring system designed to detect anomalous activity in Windows Security Event Logs using **unsupervised machine learning**.

The system collects Windows event logs through WMI, converts raw logs into security-focused time-window features, analyzes them using **Isolation Forest** and **Local Outlier Factor (LOF)**, visualizes detection results through a Flask SOC dashboard, and forwards security alerts to Splunk through HTTP Event Collector (HEC).

```text
## SOC Detection Pipeline

┌─────────────────────┐
│   Windows 10 VM     │
│   Security Logs     │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│   WMI Log Collector │
│   log_collector.py  │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│    raw_logs.csv     │
└──────────┬──────────┘
           │
           ▼
┌────────────────────────────┐
│    Feature Engineering     │
│  1-minute security windows │
└────────────┬───────────────┘
             │
             ▼
┌────────────────────────────┐
│       ML Detection         │
│                            │
│  Isolation Forest + LOF    │
└────────────┬───────────────┘
             │
             ▼
┌────────────────────────────┐
│     Anomaly Results        │
│ HIGH / MEDIUM / NORMAL     │
└────────────┬───────────────┘
             │
       ┌─────┴──────┐
       ▼            ▼
┌──────────────┐ ┌──────────────┐
│ Flask SOC    │ │ Splunk SIEM  │
│ Dashboard    │ │ HEC          │
└──────────────┘ └──────────────┘
```

---

# Overview

Security Operations Centers generate and analyze large volumes of security events from endpoints, servers, applications, and network infrastructure.

This project demonstrates a practical SOC-oriented anomaly detection pipeline using Windows Security Event Logs and unsupervised machine learning.

Instead of depending entirely on predefined detection rules, the system analyzes behavioral features and identifies unusual activity within one-minute log windows.

### Core Pipeline

```text
Windows Security Events
        ↓
Remote WMI Collection
        ↓
Raw Log Processing
        ↓
Feature Engineering
        ↓
Isolation Forest + LOF
        ↓
Anomaly Classification
        ↓
Flask SOC Dashboard
        ↓
Splunk HEC
```

---

# Key Features

### Log Collection

* Remote Windows Security Event Log collection
* WMI-based collection
* Security Event ID filtering
* CSV-based log storage
* Configurable event collection

### Feature Engineering

The system converts raw events into one-minute activity windows and extracts security-related numerical features.

Examples include:

* Failed login count
* Successful login count
* Failed login rate
* Login success ratio
* Process creation events
* Privilege events
* Logoff events
* Scheduled task events
* New user events
* Total event count
* Hour of day
* Night-time indicator
* Weekend indicator
* Unique computers
* Persistence indicator

### Machine Learning

Two unsupervised anomaly detection algorithms are used:

* Isolation Forest
* Local Outlier Factor (LOF)

The models operate without requiring a labeled training dataset.

### SOC Dashboard

The Flask dashboard provides:

* Anomaly summary
* Detection confidence
* Anomaly scores
* Security event statistics
* Login activity visualization
* Failed login monitoring
* Model agreement information
* System status
* CSV export
* Splunk forwarding controls

### Splunk Integration

Detected HIGH and MEDIUM confidence alerts can be forwarded to Splunk using:

**HTTP Event Collector (HEC)**

---

# System Architecture

The project was developed using a virtualized cybersecurity lab containing:

```text
                 HOST-ONLY NETWORK
                      │
        ┌─────────────┼─────────────┐
        │             │             │
        ▼             ▼             ▼
 Windows Host     Windows 10 VM   Ubuntu VM
 ML + Flask       Log Source      Splunk SIEM
        │
        │
        └──────────────┐
                       │
                       ▼
                 Kali Linux VM
                 Attack Simulation
```

### Lab Components

| Component     | Purpose                              |
| ------------- | ------------------------------------ |
| Windows Host  | ML processing and Flask dashboard    |
| Windows 10 VM | Security log source / victim machine |
| Kali Linux VM | Attack simulation                    |
| Ubuntu VM     | Splunk SIEM server                   |

---

# Screenshots

## 1. System Architecture

The complete architecture shows the relationship between attack simulation, Windows logs, WMI collection, feature engineering, machine-learning detection, Flask visualization, and Splunk.

**Screenshot:**
![alt text](<System Architecture.jpg>)

---

## 2. Network Topology

The lab network contains the Windows host, Windows 10 victim VM, Kali Linux attack VM, and Ubuntu Splunk VM.

**Screenshot:**
![alt text](<Network Topology.jpg>)

---

## 3. System Data Flow

The data-flow diagram illustrates the movement of security logs from collection through feature engineering and machine-learning detection to the dashboard and Splunk.

**Screenshot:**
![alt text](<System Data Flow Diagram.jpg>)
---

## 4. System Flowchart

The flowchart represents the detection process from log collection through anomaly classification and alert output.

**Screenshot:**
![alt text](<System Flowchart.jpg>)
---

## 5. Flask SOC Dashboard

The dashboard provides an SOC-style overview of detected anomalies, model results, system status, and available actions.

**Screenshot:**
![alt text](<SOC Dashboard.jpg>)
---

## 6. Alert Log Table

The alert table displays individual detected anomalies with timestamps, risk levels, model scores, security features, and anomaly status.

**Screenshot:**
![alt text](<AlertLog Table.jpg>)
---

## 7. Anomaly Score Timeline

The anomaly score timeline visualizes anomaly scores across one-minute activity windows.

**Screenshot:**
![alt text](<Anomaly Score Timeline Chart.jpg>)
---

## 8. Failed Login Activity

Event ID `4625` represents failed login activity and is monitored as an important indicator of brute-force or password-spraying behavior.

**Screenshot:**
![alt text](<Failed Login Rate Bar Chart.jpg>)
---

## 9. Login Activity — Success vs Failed

This visualization compares successful and failed authentication activity over time.

**Screenshot:**
![alt text](<Login Timeline-SuccessVsFailed.jpg>)
---

## 10. Security Event Distribution

The event distribution chart provides an overview of monitored Windows Security Event IDs.

**Screenshot:**
![alt text](<Event ID Chart.jpg>)
---

## 11. Model Agreement

The model agreement visualization shows whether anomalies were detected by Isolation Forest, LOF, or both models.

**Screenshot:**
![alt text](<Splunk Model Agreement Distribution.jpg>)
![alt text](<Splunk HEC — Anomaly Alert Events Received.jpg>)
---

# Security Events Monitored

The system focuses on Windows Security Event IDs relevant to authentication, privilege activity, process execution, and persistence.

| Event ID | Event                       | Security Relevance                     |
| -------- | --------------------------- | -------------------------------------- |
| 4624     | Successful Login            | Authentication baseline                |
| 4625     | Failed Login                | Brute-force / password-spray indicator |
| 4634     | Account Logoff              | Session activity                       |
| 4672     | Special Privileges Assigned | Privilege escalation indicator         |
| 4688     | Process Created             | Process execution / malware indicator  |
| 4698     | Scheduled Task Created      | Persistence indicator                  |
| 4720     | User Account Created        | Potential backdoor account             |

---

# Machine Learning

## Isolation Forest

Isolation Forest is an unsupervised anomaly detection algorithm that isolates unusual observations using randomly constructed decision trees.

The model is used to detect activity that differs significantly from normal log behavior.

---

## Local Outlier Factor

Local Outlier Factor (LOF) identifies observations whose local density differs from the density of their surrounding neighbors.

This provides a second perspective on anomalous behavior.

---

## Combined Detection

The project combines the outputs of both models.

```text
              ┌───────────────────┐
              │ Feature Windows   │
              └─────────┬─────────┘
                        │
              ┌─────────┴─────────┐
              ▼                   ▼
      ┌───────────────┐   ┌───────────────┐
      │ Isolation     │   │ Local Outlier │
      │ Forest        │   │ Factor        │
      └───────┬───────┘   └───────┬───────┘
              │                   │
              └─────────┬─────────┘
                        ▼
                Model Agreement
                        │
             ┌──────────┼──────────┐
             ▼          ▼          ▼
           HIGH       MEDIUM      NORMAL
```

### Confidence Logic

```text
Both models detect anomaly
        ↓
       HIGH

One model detects anomaly
        ↓
      MEDIUM

No model detects anomaly
        ↓
      NORMAL
```

---

# Feature Engineering

Raw Windows Security Event Logs are grouped into **one-minute time windows**.

The system then extracts security-focused numerical features.

```text
Raw Security Logs
       │
       ▼
Parse Timestamps
       │
       ▼
1-Minute Windows
       │
       ▼
Extract Security Features
       │
       ▼
Normalize Features
       │
       ▼
features.csv
```

Example features:

| Feature               | Security Meaning                   |
| --------------------- | ---------------------------------- |
| `failed_logins`       | Failed authentication activity     |
| `success_logins`      | Successful authentication baseline |
| `failed_login_rate`   | Rapid authentication failures      |
| `login_success_ratio` | Authentication behavior            |
| `process_events`      | Process creation activity          |
| `priv_events`         | Privilege-related activity         |
| `task_events`         | Scheduled-task persistence         |
| `new_user_events`     | User-account creation              |
| `total_events`        | Overall event volume               |
| `is_night`            | Unusual time-of-day activity       |
| `is_weekend`          | Weekend activity                   |
| `unique_computers`    | Potential lateral movement         |
| `persistence_flag`    | Persistence-related events         |

---

# Attack Simulation

The project was validated using controlled attack simulations in the lab environment.

## RDP Brute Force

Hydra was used from the Kali Linux VM to generate failed RDP authentication activity.

```text
Kali Linux
    │
    │ RDP authentication attempts
    ▼
Windows 10 VM
    │
    ▼
Event ID 4625
    │
    ▼
Log Collector
    │
    ▼
ML Detection
```

## Network Reconnaissance

Nmap was used to perform network/service reconnaissance against the Windows VM.

These activities generated security-relevant changes in the collected data for analysis.

---

# Results

The project report documents the following experimental results:

* 159 one-minute activity windows analyzed
* 15 known attack windows
* Combined model detected all 15 known attack windows in the reported test
* Isolation Forest achieved 100% recall at the reported tuned configuration
* LOF achieved 93.3% recall at the reported tuned configuration
* 39 HIGH/MEDIUM alerts were forwarded to Splunk HEC
* Flask dashboard successfully displayed anomaly information and charts

> These results are from the project's controlled lab dataset and should not be interpreted as production-world performance.

---

# Project Workflow

```text
┌──────────────────────┐
│ Windows Security Log │
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│   WMI Collection     │
│ log_collector.py     │
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│    raw_logs.csv      │
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│ Feature Engineering  │
│ 1-minute windows     │
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│     features.csv     │
└──────────┬───────────┘
           ▼
      ┌────┴─────┐
      ▼          ▼
┌───────────┐ ┌───────────┐
│ Isolation │ │    LOF    │
│  Forest   │ │           │
└─────┬─────┘ └─────┬─────┘
      └──────┬──────┘
             ▼
┌──────────────────────┐
│  Combined Detection  │
│ HIGH/MEDIUM/NORMAL   │
└──────────┬───────────┘
           ▼
      ┌────┴───────┐
      ▼            ▼
┌────────────┐ ┌─────────────┐
│   Flask    │ │   Splunk    │
│ Dashboard  │ │     HEC     │
└────────────┘ └─────────────┘
```

---

# Project Structure

```text
LogAnomalyDetect/
│
├── dashboard/
│   ├── app.py
│   └── templates/
│       ├── index.html
│       └── print.html
│
├── models/
│   ├── isolation_forest.pkl
│   └── isolation_forest_tuned.pkl
│
├── reports/
│   └── anomaly_results.png
│
├── scripts/
│   ├── anomaly_detection.py
│   ├── feature_engineering.py
│   ├── log_collector.py
│   ├── splunk_forwarder.py
│   └── tune_model.py
│
├── Screenshots/
│   ├── System-Architecture.jpg
│   ├── Network-Topology.jpg
│   ├── System-Data-Flow-Diagram.png
│   ├── System-Flowchart.png
│   ├── SOC-Dashboard.jpg
│   ├── Alert-Log-Table.jpg
│   ├── Anomaly-Score-Timeline-Chart.jpg
│   ├── Failed-Login-Rate-Bar-Chart.jpg
│   ├── Login-Timeline-SuccessVsFailed.jpg
│   ├── Event-ID-Chart.png
│   └── Splunk-Model-Agreement-Distribution.png
│
├── config.py
├── requirements.txt
├── .gitignore
└── README.md
```

---

# Technologies Used

| Technology        | Purpose                         |
| ----------------- | ------------------------------- |
| Python            | Core development                |
| Pandas            | Log processing                  |
| NumPy             | Numerical processing            |
| Scikit-learn      | Machine learning                |
| Isolation Forest  | Anomaly detection               |
| LOF               | Density-based anomaly detection |
| Flask             | SOC dashboard                   |
| WMI               | Windows event collection        |
| Requests          | Splunk HEC communication        |
| Splunk Enterprise | SIEM integration                |
| VirtualBox        | Virtual lab environment         |
| Kali Linux        | Attack simulation               |
| Hydra             | RDP brute-force simulation      |
| Nmap              | Network reconnaissance          |

---

# Requirements

Recommended environment:

```text
Python 3.10+
Windows host for WMI-based collection
VirtualBox
Windows 10 VM
Kali Linux VM
Ubuntu/Splunk VM
```

Python dependencies are listed in:

```text
requirements.txt
```

---

# Installation

## 1. Clone the Repository

```bash
git clone https://github.com/777wolf/AI-Powered-Log-Anomaly-Detection-System-for-SOC-Environments-.git
```

```bash
cd AI-Powered-Log-Anomaly-Detection-System-for-SOC-Environments-
```

---

## 2. Create a Virtual Environment

Windows:

```powershell
python -m venv myproject
```

Activate it:

```powershell
.\myproject\Scripts\Activate.ps1
```

---

## 3. Install Dependencies

```powershell
pip install -r requirements.txt
```

---

# Configuration

Sensitive credentials should **never** be committed to GitHub.

Create a local `.env` file:

```text
SPLUNK_TOKEN=your-splunk-hec-token
```

The `.env` file is excluded through `.gitignore`.

The Splunk configuration is handled through environment variables in `config.py`.

> Do not place real passwords, Splunk HEC tokens, or other credentials directly inside source code.

---

# Running the Pipeline

## Step 1 — Collect Logs

Run the log collector:

```powershell
python scripts/log_collector.py <username> <password>
```

This collects Windows Security Event Logs and creates:

```text
data/raw_logs.csv
```

---

## Step 2 — Feature Engineering

Run:

```powershell
python scripts/feature_engineering.py
```

This generates:

```text
data/features.csv
```

---

## Step 3 — Run Anomaly Detection

Run:

```powershell
python scripts/anomaly_detection.py
```

The detection process uses:

```text
Isolation Forest
        +
       LOF
        ↓
Anomaly Results
```

---

## Step 4 — Tune the Models

Run:

```powershell
python scripts/tune_model.py
```

The tuned model files are stored in:

```text
models/
```

---

## Step 5 — Start the Flask Dashboard

Run:

```powershell
python dashboard/app.py
```

Then open:

```text
http://127.0.0.1:5000
```

---

# Splunk Integration

The project uses Splunk HTTP Event Collector (HEC) to forward anomaly alerts.

The forwarding pipeline is:

```text
ML Detection
     │
     ▼
HIGH / MEDIUM Alerts
     │
     ▼
Splunk Forwarder
     │
     ▼
HTTP Event Collector
     │
     ▼
Splunk SIEM
```

Example Splunk search:

```text
sourcetype=anomaly_detection
```

---

# Detection Output

The system categorizes activity into three confidence levels:

| Level  | Meaning                                            |
| ------ | -------------------------------------------------- |
| HIGH   | Both anomaly detection models flagged the activity |
| MEDIUM | One model flagged the activity                     |
| NORMAL | No model flagged the activity                      |

Example:

```text
HIGH
├── Isolation Forest → ANOMALY
└── LOF             → ANOMALY
```

---

# Limitations

The current implementation has several limitations:

* Log collection is performed on demand rather than as a continuous stream.
* Detection latency depends on when collection is triggered.
* Model contamination parameters require tuning for significantly different environments.
* Validation was performed primarily against RDP brute-force activity and Nmap reconnaissance.
* The current pipeline focuses on Windows Security Event Logs.
* Network, application, and cloud logs are not currently integrated.
* Feature normalization depends on the current dataset.
* The project is a controlled research/educational implementation rather than a production SOC platform.

---

# Future Scope

Potential future improvements include:

* Continuous real-time log streaming
* Apache Kafka integration
* Cloud log ingestion
* AWS CloudTrail integration
* Azure Monitor integration
* GCP log integration
* SOAR integration
* Automated incident response
* MITRE ATT&CK technique mapping
* Multi-source log correlation
* Deep-learning-based log anomaly detection
* Active Directory security monitoring
* Additional attack scenario validation

---

# Security Considerations

This project is intended for **authorized security testing and monitoring environments**.

When deploying or modifying the project:

* Never commit credentials to Git.
* Store API tokens in environment variables.
* Use test VMs for attack simulations.
* Do not perform brute-force or reconnaissance activity against systems without authorization.
* Rotate credentials if they have accidentally been exposed.
* Keep `.env` files out of version control.

---

# Project Status

**Status: Completed Academic / Research Project**

The project demonstrates an end-to-end SOC-oriented anomaly detection pipeline covering:

```text
Log Collection
      ↓
Feature Engineering
      ↓
Unsupervised ML
      ↓
Anomaly Detection
      ↓
SOC Dashboard
      ↓
Splunk SIEM
```

---

# Disclaimer

This project is intended for **educational, research, cybersecurity learning, and authorized security monitoring purposes only**.

Attack simulations should only be performed against systems and networks for which you have explicit authorization.

---

# Author

**Tushar Kumar Swami**

---

<p align="center">

**AI-Powered Log Anomaly Detection System**

`Detect` · `Analyze` · `Alert`

Built for cybersecurity learning and SOC research.

</p>
```
