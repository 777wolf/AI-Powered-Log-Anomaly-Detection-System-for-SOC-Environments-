# config.py — Central config for the project
import os
# Paths
DATA_PATH = "data/"
LOG_PATH = "logs/"
MODEL_PATH = "models/"
REPORT_PATH = "reports/"

# Windows Event IDs to collect
EVENT_IDS = [4624, 4625, 4634, 4672, 4688, 4698, 4720]

# Splunk HEC config (fill after HEC token setup)
SPLUNK_HOST  = "192.168.56.101"
SPLUNK_PORT  = 8088
SPLUNK_TOKEN = os.getenv("ea99cd86-5243-4016-8b4c-452fa9eb5847")

# ML config
CONTAMINATION = 0.15  # Expected 5% anomaly rate
RANDOM_STATE = 42
