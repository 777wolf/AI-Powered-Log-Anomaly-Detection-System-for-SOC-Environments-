# scripts/feature_engineering.py
# Purpose: Transform raw log CSV into ML-ready numerical features

import pandas as pd
import numpy as np
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import DATA_PATH

def parse_timestamp(ts):
    """
    Convert WMI timestamp format to datetime.
    WMI format: 20260418120909.692435-000
    """
    try:
        # Extract just the date+time part before the dot
        ts_clean = str(ts).split('.')[0]
        return pd.to_datetime(ts_clean, format='%Y%m%d%H%M%S')
    except:
        return pd.NaT


def load_and_clean(path):
    """
    Load raw_logs.csv and do basic cleaning.
    """
    print("[*] Loading raw logs...")
    df = pd.read_csv(path)
    print(f"[+] Loaded {len(df)} rows")

    # Convert timestamp
    df['timestamp'] = df['timestamp'].apply(parse_timestamp)
    df = df.dropna(subset=['timestamp'])
    df = df.sort_values('timestamp').reset_index(drop=True)

    print(f"[+] After timestamp cleaning: {len(df)} rows")
    print(f"[+] Time range: {df['timestamp'].min()} to {df['timestamp'].max()}")
    return df


def extract_features(df):
    """
    Engineer features from raw logs.
    Groups events into 1-minute windows and extracts
    security-relevant numerical features per window.
    """
    print("\n[*] Engineering features...")

    # Round timestamps to 1-minute windows
    # This is called time-windowing — standard technique in log analysis
    # Instead of analyzing each event alone, we look at patterns per minute
    df['time_window'] = df['timestamp'].dt.floor('1min')

    # ── Group by time window and compute features ──
    features = []

    for window, group in df.groupby('time_window'):

        # Count each event type in this minute
        event_counts = group['event_id'].value_counts()

        failed_logins     = event_counts.get(4625, 0)  # failed login count
        success_logins    = event_counts.get(4624, 0)  # successful login count
        logoffs           = event_counts.get(4634, 0)  # logoff count
        priv_events       = event_counts.get(4672, 0)  # privilege assignment
        process_events    = event_counts.get(4688, 0)  # process creation
        task_events       = event_counts.get(4698, 0)  # scheduled task created
        new_user_events   = event_counts.get(4720, 0)  # new user account

        total_events = len(group)

        # Login success ratio: low ratio = many failures before success = brute force
        # Avoid division by zero
        total_auth = failed_logins + success_logins
        login_success_ratio = success_logins / total_auth if total_auth > 0 else 1.0

        # Failed login rate: how many failures per minute
        failed_login_rate = failed_logins  # already per-minute since we windowed by 1 min

        # Process creation rate: spike = malware or suspicious activity
        process_rate = process_events

        # Privilege rate: sudden spike = privilege escalation
        priv_rate = priv_events

        # Time-based features
        hour_of_day = window.hour
        is_night    = 1 if (hour_of_day >= 22 or hour_of_day <= 5) else 0
        is_weekend  = 1 if window.weekday() >= 5 else 0

        # Unique computers seen in this window
        # More unique sources = lateral movement
        unique_computers = group['computer'].nunique()

        # Suspicious flag: 1 if new user or scheduled task created
        persistence_flag = 1 if (task_events > 0 or new_user_events > 0) else 0

        features.append({
            'time_window'         : window,
            'total_events'        : total_events,
            'failed_logins'       : failed_logins,
            'success_logins'      : success_logins,
            'failed_login_rate'   : failed_login_rate,
            'login_success_ratio' : round(login_success_ratio, 4),
            'priv_events'         : priv_events,
            'process_events'      : process_events,
            'logoffs'             : logoffs,
            'task_events'         : task_events,
            'new_user_events'     : new_user_events,
            'hour_of_day'         : hour_of_day,
            'is_night'            : is_night,
            'is_weekend'          : is_weekend,
            'unique_computers'    : unique_computers,
            'persistence_flag'    : persistence_flag,
        })

    feature_df = pd.DataFrame(features)
    print(f"[+] Created {len(feature_df)} time windows (1 row = 1 minute of activity)")
    print(f"[+] Features per window: {len(feature_df.columns) - 1}")  # -1 for time_window col
    return feature_df


def normalize_features(feature_df):
    """
    Apply Min-Max normalization to numerical features.
    Normalization scales all values to range 0-1.
    This is required because ML models treat large numbers
    as more important than small numbers by default.
    Example: process_events might be 4000 while is_night is 0 or 1.
    Without normalization the model focuses only on process_events.
    """
    from sklearn.preprocessing import MinMaxScaler

    print("\n[*] Normalizing features...")

    # Columns to normalize (all numerical except time and binary flags)
    cols_to_normalize = [
        'total_events', 'failed_logins', 'success_logins',
        'failed_login_rate', 'login_success_ratio',
        'priv_events', 'process_events', 'logoffs',
        'task_events', 'new_user_events', 'unique_computers'
    ]

    scaler = MinMaxScaler()
    feature_df[cols_to_normalize] = scaler.fit_transform(feature_df[cols_to_normalize])

    print("[+] Normalization complete. All values now in range [0, 1]")
    return feature_df, scaler


def show_summary(feature_df):
    print("\n[*] Feature Summary:")
    print(feature_df.describe().round(4))

    print("\n[*] Windows with failed logins > 0:")
    suspicious = feature_df[feature_df['failed_logins'] > 0]
    print(f"    {len(suspicious)} out of {len(feature_df)} windows had failed logins")

    print("\n[*] Night-time activity windows:")
    night = feature_df[feature_df['is_night'] == 1]
    print(f"    {len(night)} windows with activity between 10PM - 5AM")


if __name__ == "__main__":

    raw_path = os.path.join(DATA_PATH, "raw_logs.csv")

    # Step 1: Load and clean
    df = load_and_clean(raw_path)

    # Step 2: Extract features
    feature_df = extract_features(df)

    # Step 3: Normalize
    feature_df, scaler = normalize_features(feature_df)

    # Step 4: Show summary
    show_summary(feature_df)

    # Step 5: Save
    out_path = os.path.join(DATA_PATH, "features.csv")
    feature_df.to_csv(out_path, index=False)
    print(f"\n[+] Features saved to {out_path}")
    print(f"[+] Shape: {feature_df.shape[0]} rows x {feature_df.shape[1]} columns")
    print("\n[+] Phase 3 complete. Ready for ML models in Phase 4.")