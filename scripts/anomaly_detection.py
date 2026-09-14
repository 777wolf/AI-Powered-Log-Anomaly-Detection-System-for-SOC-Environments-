# scripts/anomaly_detection.py
# Purpose: Train Isolation Forest and LOF models on features
# and detect anomalous time windows automatically

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import os
import sys
import joblib

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import DATA_PATH, MODEL_PATH, CONTAMINATION, RANDOM_STATE

# ── Feature columns to feed into ML models ──
# We exclude time_window (not a number) and binary flags
# (already captured in other features)
FEATURE_COLS = [
    'total_events',
    'failed_logins',
    'success_logins',
    'failed_login_rate',
    'login_success_ratio',
    'priv_events',
    'process_events',
    'logoffs',
    'hour_of_day',
    'unique_computers',
]


def load_features():
    path = os.path.join(DATA_PATH, "features.csv")
    df = pd.read_csv(path)
    print(f"[+] Loaded features: {df.shape[0]} windows x {df.shape[1]} columns")
    return df


def run_isolation_forest(df, X):
    """
    Isolation Forest works by randomly selecting a feature
    and then randomly selecting a split value between the
    max and min of that feature.

    Anomalies are isolated in fewer splits because they are
    rare and different from the majority of data points.
    Normal points require many more splits to isolate.

    contamination = expected proportion of anomalies in data.
    We set 0.05 = expect 5% of windows to be anomalous.
    """
    from sklearn.ensemble import IsolationForest

    print("\n[*] Running Isolation Forest...")

    model = IsolationForest(
        contamination=CONTAMINATION,  # expect 5% anomalies
        random_state=RANDOM_STATE,    # for reproducibility
        n_estimators=100,             # number of trees in forest
        max_samples='auto'            # samples per tree
    )

    # fit_predict returns:
    # -1 = anomaly
    #  1 = normal
    df['if_label'] = model.fit_predict(X)

    # decision_function returns raw anomaly score
    # more negative = more anomalous
    df['if_score'] = model.decision_function(X)

    # Convert to easier reading:
    # Flip score so higher = more anomalous
    df['if_score_flipped'] = -df['if_score']

    anomalies = df[df['if_label'] == -1]
    print(f"[+] Isolation Forest detected {len(anomalies)} anomalous windows")
    print(f"    out of {len(df)} total windows ({len(anomalies)/len(df)*100:.1f}%)")

    # Save model
    model_path = os.path.join(MODEL_PATH, "isolation_forest.pkl")
    joblib.dump(model, model_path)
    print(f"[+] Model saved to {model_path}")

    return df, model


def run_lof(df, X):
    """
    Local Outlier Factor compares the density of each point
    to its k nearest neighbors.

    A point in a sparse region (surrounded by few neighbors)
    compared to a dense cluster is flagged as an outlier.

    novelty=False means we use fit_predict (no separate test set).
    contamination=0.05 means flag top 5% most outlying points.
    """
    from sklearn.neighbors import LocalOutlierFactor

    print("\n[*] Running Local Outlier Factor (LOF)...")

    model = LocalOutlierFactor(
        n_neighbors=10,               # compare each point to 10 nearest neighbors
        contamination=CONTAMINATION,  # expect 5% anomalies
    )

    # fit_predict returns -1 (anomaly) or 1 (normal)
    df['lof_label'] = model.fit_predict(X)

    # negative_outlier_factor_: more negative = more anomalous
    df['lof_score'] = -model.negative_outlier_factor_

    anomalies = df[df['lof_label'] == -1]
    print(f"[+] LOF detected {len(anomalies)} anomalous windows")
    print(f"    out of {len(df)} total windows ({len(anomalies)/len(df)*100:.1f}%)")

    return df


def combine_results(df):
    """
    Combine both model results.
    A window flagged by BOTH models = high confidence anomaly.
    A window flagged by ONE model = medium confidence anomaly.
    """
    print("\n[*] Combining model results...")

    # Count how many models flagged each window
    df['models_flagged'] = 0
    df.loc[df['if_label'] == -1, 'models_flagged'] += 1
    df.loc[df['lof_label'] == -1, 'models_flagged'] += 1

    # Assign confidence level
    def confidence(row):
        if row['models_flagged'] == 2:
            return 'HIGH'
        elif row['models_flagged'] == 1:
            return 'MEDIUM'
        else:
            return 'NORMAL'

    df['confidence'] = df.apply(confidence, axis=1)

    # Combined anomaly score (average of both normalized scores)
    df['combined_score'] = (
        df['if_score_flipped'] / df['if_score_flipped'].max() +
        df['lof_score'] / df['lof_score'].max()
    ) / 2

    return df


def show_results(df):
    print("\n" + "="*60)
    print("  ANOMALY DETECTION RESULTS")
    print("="*60)

    high   = df[df['confidence'] == 'HIGH']
    medium = df[df['confidence'] == 'MEDIUM']
    normal = df[df['confidence'] == 'NORMAL']

    print(f"\n  HIGH confidence anomalies   : {len(high)}")
    print(f"  MEDIUM confidence anomalies : {len(medium)}")
    print(f"  Normal windows              : {len(normal)}")
    print(f"  Total windows analyzed      : {len(df)}")

    print("\n[*] HIGH Confidence Anomalies:")
    print("-"*60)
    if len(high) > 0:
        cols = ['time_window','failed_logins','login_success_ratio',
                'process_events','combined_score','confidence']
        print(high[cols].to_string(index=False))
    else:
        print("  None detected at HIGH confidence")

    print("\n[*] MEDIUM Confidence Anomalies:")
    print("-"*60)
    if len(medium) > 0:
        cols = ['time_window','failed_logins','login_success_ratio',
                'process_events','combined_score','confidence']
        print(medium[cols].to_string(index=False))

    # Validation: check overlap with known attack windows
    # These are windows we KNOW had attack activity (from Phase 2)
    known_attack_windows = [
        '2026-03-01 17:10:00', '2026-03-01 17:19:00',
        '2026-03-01 17:20:00', '2026-03-01 17:21:00',
        '2026-03-01 17:22:00', '2026-03-02 13:19:00',
        '2026-04-16 08:24:00', '2026-04-16 08:25:00',
        '2026-04-16 08:28:00', '2026-04-16 08:36:00',
        '2026-04-16 08:37:00', '2026-04-16 08:38:00',
        '2026-04-18 11:31:00', '2026-04-18 11:55:00',
        '2026-04-18 11:56:00',
    ]

    print("\n[*] Validation against known attack windows:")
    print("-"*60)
    detected_attacks = df[
        (df['time_window'].isin(known_attack_windows)) &
        (df['confidence'] != 'NORMAL')
    ]
    print(f"  Known attack windows    : {len(known_attack_windows)}")
    print(f"  Correctly detected      : {len(detected_attacks)}")
    missed = len(known_attack_windows) - len(detected_attacks)
    print(f"  Missed                  : {missed}")
    if len(known_attack_windows) > 0:
        recall = len(detected_attacks) / len(known_attack_windows) * 100
        print(f"  Detection Rate (Recall) : {recall:.1f}%")


def plot_results(df):
    """
    Generate visualization of anomaly scores over time.
    Saved to reports/ folder.
    """
    print("\n[*] Generating anomaly score plot...")

    fig, axes = plt.subplots(3, 1, figsize=(14, 10))
    fig.suptitle('AI-Powered Log Anomaly Detection Results', fontsize=14, fontweight='bold')

    df['time_window'] = pd.to_datetime(df['time_window'])
    df_sorted = df.sort_values('time_window')

    # Plot 1: Failed logins over time
    axes[0].bar(range(len(df_sorted)), df_sorted['failed_logins'],
                color='red', alpha=0.7, label='Failed Logins')
    axes[0].set_title('Failed Login Rate per Minute Window')
    axes[0].set_ylabel('Normalized Count')
    axes[0].legend()

    # Plot 2: Isolation Forest anomaly score
    colors_if = ['red' if l == -1 else 'steelblue' for l in df_sorted['if_label']]
    axes[1].scatter(range(len(df_sorted)), df_sorted['if_score_flipped'],
                    c=colors_if, alpha=0.8, s=30)
    axes[1].set_title('Isolation Forest Anomaly Score (Red = Anomaly)')
    axes[1].set_ylabel('Anomaly Score')

    # Plot 3: Combined score
    colors_comb = []
    for c in df_sorted['confidence']:
        if c == 'HIGH':
            colors_comb.append('red')
        elif c == 'MEDIUM':
            colors_comb.append('orange')
        else:
            colors_comb.append('steelblue')

    axes[2].scatter(range(len(df_sorted)), df_sorted['combined_score'],
                    c=colors_comb, alpha=0.8, s=40)
    axes[2].set_title('Combined Anomaly Score (Red=HIGH, Orange=MEDIUM, Blue=Normal)')
    axes[2].set_ylabel('Combined Score')
    axes[2].set_xlabel('Time Window Index')

    plt.tight_layout()
    plot_path = os.path.join('reports', 'anomaly_results.png')
    plt.savefig(plot_path, dpi=150, bbox_inches='tight')
    print(f"[+] Plot saved to {plot_path}")
    plt.show()


if __name__ == "__main__":

    print("="*60)
    print("  Phase 4: Anomaly Detection")
    print("="*60)

    # Load features
    df = load_features()

    # Extract feature matrix (numbers only, no timestamps)
    X = df[FEATURE_COLS].values

    # Run models
    df, if_model = run_isolation_forest(df, X)
    df = run_lof(df, X)

    # Combine results
    df = combine_results(df)

    # Show results
    show_results(df)

    # Plot
    plot_results(df)

    # Save final results
    out_path = os.path.join(DATA_PATH, "anomaly_results.csv")
    df.to_csv(out_path, index=False)
    print(f"\n[+] Full results saved to {out_path}")
    print("\n[+] Phase 4 complete. Ready for dashboard in Phase 5.")