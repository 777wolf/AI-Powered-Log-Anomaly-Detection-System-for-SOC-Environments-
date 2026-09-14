# AI-Powered Log Anomaly Detection System for SOC Environments

An AI/ML-based log anomaly detection system designed to help Security Operations Center (SOC) environments identify potentially anomalous activity in Windows event logs.

## Overview

The system collects Windows event logs, performs feature engineering, and applies unsupervised machine-learning algorithms to identify anomalous log activity.

It also provides a Flask-based dashboard for viewing detection results and supports forwarding log data to Splunk for SIEM integration.

## Features

- Windows event log collection using WMI
- Log preprocessing and feature engineering
- Unsupervised anomaly detection
- Isolation Forest-based detection
- Local Outlier Factor (LOF)-based detection
- Model tuning
- Flask web dashboard
- Splunk HEC integration
- Anomaly result visualization

## Technologies Used

- Python
- Flask
- Scikit-learn
- Pandas
- NumPy
- WMI
- Splunk
- HTML/CSS
- Isolation Forest
- Local Outlier Factor (LOF)

## Project Structure

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
├── config.py
├── .gitignore
└── README.md

## Machine Learning

The project uses unsupervised learning techniques to detect potentially anomalous log events.

### Isolation Forest

Isolation Forest is used to identify observations that are different from the majority of the dataset.

### Local Outlier Factor

Local Outlier Factor (LOF) evaluates the local density of observations to identify data points that differ significantly from their surrounding data.

## Workflow

## Workflow

```text
Windows Event Logs
        │
        ▼
   Log Collection
        │
        ▼
 Feature Engineering
        │
        ▼
 Anomaly Detection
   ┌────┴────┐
   ▼         ▼
Isolation    LOF
 Forest
   └────┬────┘
        ▼
 Anomaly Results
   ┌────┴──────────┐
   ▼               ▼
Flask Dashboard   Splunk

## Configuration

Sensitive configuration values such as the Splunk HEC token should be stored in environment variables rather than committed to the repository.

Create a `.env` file locally:

```
SPLUNK_TOKEN=your-splunk-hec-token
```

The `.env` file is excluded from Git using `.gitignore`.

## Running the Projectgit status

Clone the repository:

```bash
git clone https://github.com/777wolf/AI-Powered-Log-Anomaly-Detection-System-for-SOC-Environments-.git
cd AI-Powered-Log-Anomaly-Detection-System-for-SOC-Environments-
```

Install the required Python dependencies:

```bash
pip install -r requirements.txt
```

Configure the required environment variables and run the appropriate project scripts.

## Project Status

This project is developed as a cybersecurity/SOC-focused machine-learning project for log analysis and anomaly detection.

## Disclaimer

This project is intended for educational, research, and authorized security monitoring purposes only.
