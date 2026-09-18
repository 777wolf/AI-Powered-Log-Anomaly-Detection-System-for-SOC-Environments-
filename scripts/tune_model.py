# scripts/tune_model.py
# Purpose: Tune Isolation Forest and LOF to maximize detection rate
# Tests multiple contamination values and n_neighbors combinations
# Documents which settings give best results

import pandas as pd
import numpy as np
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import DATA_PATH, MODEL_PATH, RANDOM_STATE

# Known attack windows from Phase 2 (ground truth)
# Known attack windows from evaluation dataset
KNOWN_ATTACKS_FILE = os.path.join(DATA_PATH, "known_attacks.csv")

KNOWN_ATTACKS = (
    pd.read_csv(KNOWN_ATTACKS_FILE)["time_window"]
    .astype(str)
    .tolist()
)

FEATURE_COLS = [
    'total_events', 'failed_logins', 'success_logins',
    'failed_login_rate', 'login_success_ratio',
    'priv_events', 'process_events', 'logoffs',
    'hour_of_day', 'unique_computers',
]


def evaluate(df, labels):
    """
    Given predicted labels (-1=anomaly, 1=normal),
    calculate detection rate and false positive rate.
    """
    df = df.copy()
    df['predicted'] = labels

    # True Positives: known attack windows flagged as anomaly
    detected = df[
        (df['time_window'].isin(KNOWN_ATTACKS)) &
        (df['predicted'] == -1)
    ]

    # False Positives: non-attack windows flagged as anomaly
    fp = df[
        (~df['time_window'].isin(KNOWN_ATTACKS)) &
        (df['predicted'] == -1)
    ]

    total_attacks = len(KNOWN_ATTACKS)
    tp = len(detected)
    recall = tp / total_attacks * 100

    total_normal = len(df) - total_attacks
    fpr = len(fp) / total_normal * 100 if total_normal > 0 else 0

    return tp, recall, len(fp), fpr


def tune_isolation_forest(df, X):
    from sklearn.ensemble import IsolationForest

    print("\n" + "="*60)
    print("  TUNING ISOLATION FOREST")
    print("="*60)
    print(f"{'Contamination':>15} {'n_estimators':>13} {'Detected':>9} {'Recall%':>8} {'FP':>5} {'FPR%':>7}")
    print("-"*60)

    best = {'recall': 0, 'params': {}, 'labels': None}

    contamination_values = [0.05, 0.08, 0.10, 0.12, 0.15, 0.20]
    estimator_values = [50, 100, 200]

    for cont in contamination_values:
        for n_est in estimator_values:
            model = IsolationForest(
                contamination=cont,
                n_estimators=n_est,
                random_state=RANDOM_STATE,
                max_samples='auto'
            )
            labels = model.fit_predict(X)
            tp, recall, fp, fpr = evaluate(df, labels)

            print(f"{cont:>15.2f} {n_est:>13} {tp:>9} {recall:>7.1f}% {fp:>5} {fpr:>6.1f}%")

            if recall > best['recall']:
                best['recall'] = recall
                best['params'] = {'contamination': cont, 'n_estimators': n_est}
                best['labels'] = labels
                best['model'] = model

    print(f"\n[+] Best IF settings: {best['params']}")
    print(f"[+] Best IF recall:   {best['recall']:.1f}%")
    return best


def tune_lof(df, X):
    from sklearn.neighbors import LocalOutlierFactor

    print("\n" + "="*60)
    print("  TUNING LOCAL OUTLIER FACTOR")
    print("="*60)
    print(f"{'Contamination':>15} {'n_neighbors':>12} {'Detected':>9} {'Recall%':>8} {'FP':>5} {'FPR%':>7}")
    print("-"*60)

    best = {'recall': 0, 'params': {}, 'labels': None}

    contamination_values = [0.05, 0.08, 0.10, 0.12, 0.15, 0.20]
    neighbor_values = [5, 10, 15, 20]

    for cont in contamination_values:
        for n_neighbors in neighbor_values:
            model = LocalOutlierFactor(
                contamination=cont,
                n_neighbors=n_neighbors,
            )
            labels = model.fit_predict(X)
            tp, recall, fp, fpr = evaluate(df, labels)

            print(f"{cont:>15.2f} {n_neighbors:>12} {tp:>9} {recall:>7.1f}% {fp:>5} {fpr:>6.1f}%")

            if recall > best['recall']:
                best['recall'] = recall
                best['params'] = {'contamination': cont, 'n_neighbors': n_neighbors}
                best['labels'] = labels

    print(f"\n[+] Best LOF settings: {best['params']}")
    print(f"[+] Best LOF recall:   {best['recall']:.1f}%")
    return best


def run_best_combined(df, X, if_best, lof_best):
    """
    Run both models with best settings and combine results.
    Window flagged by either model = anomaly (OR logic).
    This maximizes recall at cost of some false positives.
    """
    from sklearn.ensemble import IsolationForest
    from sklearn.neighbors import LocalOutlierFactor
    import joblib

    print("\n" + "="*60)
    print("  FINAL COMBINED MODEL (BEST SETTINGS)")
    print("="*60)

    # Best Isolation Forest
    if_model = IsolationForest(**if_best['params'], random_state=RANDOM_STATE)
    if_labels = if_model.fit_predict(X)
    if_scores = -if_model.decision_function(X)

    # Best LOF
    lof_model = LocalOutlierFactor(**lof_best['params'])
    lof_labels = lof_model.fit_predict(X)
    lof_scores = -lof_model.negative_outlier_factor_

    df['if_label']   = if_labels
    df['lof_label']  = lof_labels
    df['if_score']   = if_scores
    df['lof_score']  = lof_scores

    # OR combination: flagged by either model = anomaly
    df['combined_label'] = np.where(
        (df['if_label'] == -1) | (df['lof_label'] == -1), -1, 1
    )

    # Confidence level
    df['models_flagged'] = 0
    df.loc[df['if_label']  == -1, 'models_flagged'] += 1
    df.loc[df['lof_label'] == -1, 'models_flagged'] += 1

    def confidence(row):
        if row['models_flagged'] == 2: return 'HIGH'
        elif row['models_flagged'] == 1: return 'MEDIUM'
        else: return 'NORMAL'

    df['confidence'] = df.apply(confidence, axis=1)

    # Combined score
    df['combined_score'] = (
        df['if_score'] / df['if_score'].max() +
        df['lof_score'] / df['lof_score'].max()
    ) / 2

    # Evaluate combined
    tp, recall, fp, fpr = evaluate(df, df['combined_label'])

    print(f"\n  Detection Rate (Recall) : {recall:.1f}%")
    print(f"  Correctly detected      : {tp} / {len(KNOWN_ATTACKS)}")
    print(f"  False Positives         : {fp}")
    print(f"  False Positive Rate     : {fpr:.1f}%")

    print("\n[*] Detected attack windows:")
    detected = df[
        (df['time_window'].isin(KNOWN_ATTACKS)) &
        (df['combined_label'] == -1)
    ][['time_window', 'failed_logins', 'login_success_ratio', 'confidence', 'combined_score']]
    print(detected.to_string(index=False))

    print("\n[*] Missed attack windows:")
    missed = df[
        (df['time_window'].isin(KNOWN_ATTACKS)) &
        (df['combined_label'] == 1)
    ][['time_window', 'failed_logins', 'login_success_ratio']]
    print(missed.to_string(index=False))

    # Save tuned model
    joblib.dump(if_model, os.path.join(MODEL_PATH, "isolation_forest_tuned.pkl"))
    print(f"\n[+] Tuned model saved to models/isolation_forest_tuned.pkl")

    # Save results
    df.to_csv(os.path.join(DATA_PATH, "anomaly_results_tuned.csv"), index=False)
    print(f"[+] Tuned results saved to data/anomaly_results_tuned.csv")

    return df


if __name__ == "__main__":

    print("="*60)
    print("  Model Tuning: Isolation Forest + LOF")
    print("="*60)

    # Load features
    df = pd.read_csv(os.path.join(DATA_PATH, "features.csv"))
    print(f"[+] Loaded {len(df)} windows")

    X = df[FEATURE_COLS].values

    # Tune both models
    if_best  = tune_isolation_forest(df.copy(), X)
    lof_best = tune_lof(df.copy(), X)

    # Run combined best
    df_final = run_best_combined(df.copy(), X, if_best, lof_best)

    print("\n[+] Tuning complete.")