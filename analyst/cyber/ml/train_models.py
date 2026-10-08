"""
CyberAnalyst AI - reproducible ML training pipeline.

This script creates a controlled labelled training set from realistic network/
healthcare telemetry distributions. It is deliberately separated from the live
application so model training does not happen on every event.

You can later add CIC-IDS2017/UNSW-NB15 CSVs through --csv and map their labels
to the CyberAnalyst classes. The script never pretends those datasets are
healthcare-specific.
"""

from pathlib import Path
import argparse, json
import numpy as np
import pandas as pd
import joblib

from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, precision_recall_fscore_support
from xgboost import XGBClassifier

ROOT = Path(__file__).resolve().parents[1]
MODEL_DIR = ROOT / "ml" / "models"
MODEL_DIR.mkdir(parents=True, exist_ok=True)

CLASSES = [
    "Normal",
    "Brute Force",
    "Port Scan",
    "SQL Injection",
    "Unauthorized Access",
    "Privilege Escalation",
    "Data Exfiltration",
]

FEATURES = [
    "src_port", "dest_port", "severity", "is_alert", "signature_length",
    "is_http", "request_rate", "failed_login_count", "byte_count",
    "flow_duration_ms"
]

def synthetic_dataset(n_per_class=350, seed=42):
    rng = np.random.default_rng(seed)
    rows = []

    for label_id, label in enumerate(CLASSES):
        for _ in range(n_per_class):
            src_port = rng.integers(1024, 65535)
            dest_port = 5000
            severity = 3
            is_alert = 0
            signature_length = rng.integers(0, 25)
            is_http = 1
            request_rate = max(0, rng.normal(2, 1))
            failed_login_count = max(0, rng.normal(0.5, 1))
            byte_count = max(100, rng.normal(1200, 300))
            flow_duration_ms = max(10, rng.normal(150, 60))

            if label == "Brute Force":
                severity, is_alert = 2, 1
                request_rate = rng.normal(18, 4)
                failed_login_count = rng.normal(15, 4)
                signature_length = rng.normal(60, 8)
            elif label == "Port Scan":
                severity, is_alert = 2, 1
                dest_port = int(rng.choice([22, 80, 443, 5000, 8080]))
                request_rate = rng.normal(35, 7)
                signature_length = rng.normal(42, 7)
                is_http = int(rng.random() > .45)
            elif label == "SQL Injection":
                severity, is_alert = 1, 1
                request_rate = rng.normal(8, 3)
                signature_length = rng.normal(55, 10)
                byte_count = rng.normal(1800, 400)
            elif label == "Unauthorized Access":
                severity, is_alert = 1, 1
                failed_login_count = rng.normal(4, 2)
                request_rate = rng.normal(7, 2)
                signature_length = rng.normal(58, 9)
            elif label == "Privilege Escalation":
                severity, is_alert = 1, 1
                request_rate = rng.normal(5, 2)
                signature_length = rng.normal(62, 9)
                byte_count = rng.normal(2500, 700)
            elif label == "Data Exfiltration":
                severity, is_alert = 1, 1
                request_rate = rng.normal(10, 3)
                byte_count = rng.normal(18000, 5000)
                flow_duration_ms = rng.normal(1400, 350)
                signature_length = rng.normal(54, 8)

            rows.append([
                src_port, dest_port, max(1, min(3, severity)), is_alert,
                max(0, signature_length), is_http, max(0, request_rate),
                max(0, failed_login_count), max(50, byte_count),
                max(5, flow_duration_ms), label_id
            ])

    return pd.DataFrame(rows, columns=FEATURES + ["label_id"])

def train(df):
    X = df[FEATURES]
    y = df["label_id"].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Isolation Forest learns the normal behavior distribution only.
    normal_X = X_train[y_train == 0]
    iso = IsolationForest(
        n_estimators=200,
        contamination=0.08,
        random_state=42,
        n_jobs=-1
    )
    iso.fit(normal_X)

    # XGBoost performs multiclass threat classification.
    xgb = XGBClassifier(
        n_estimators=180,
        max_depth=5,
        learning_rate=0.08,
        subsample=0.9,
        colsample_bytree=0.9,
        objective="multi:softprob",
        num_class=len(CLASSES),
        eval_metric="mlogloss",
        random_state=42,
        n_jobs=2
    )
    xgb.fit(X_train, y_train)

    pred = xgb.predict(X_test)
    acc = float(accuracy_score(y_test, pred))
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_test, pred, average="weighted", zero_division=0
    )

    report = classification_report(
        y_test, pred, target_names=CLASSES, output_dict=True, zero_division=0
    )

    joblib.dump(iso, MODEL_DIR / "isolation_forest.joblib")
    joblib.dump(xgb, MODEL_DIR / "xgboost_classifier.joblib")

    metadata = {
        "feature_names": FEATURES,
        "classes": CLASSES,
        "training_rows": int(len(df)),
        "test_rows": int(len(X_test)),
        "accuracy": acc,
        "weighted_precision": float(precision),
        "weighted_recall": float(recall),
        "weighted_f1": float(f1),
        "training_source": "controlled synthetic network/healthcare telemetry",
        "note": "Replace/add public network datasets after label mapping; do not describe synthetic data as real-world measured performance."
    }
    (MODEL_DIR / "model_metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    print(json.dumps(metadata, indent=2))
    print("\nSaved models to:", MODEL_DIR)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", help="Optional labelled CSV using the project's feature names.")
    parser.add_argument("--n-per-class", type=int, default=350)
    args = parser.parse_args()

    if args.csv:
        df = pd.read_csv(args.csv)
        missing = [x for x in FEATURES + ["label_id"] if x not in df.columns]
        if missing:
            raise SystemExit(f"CSV is missing columns: {missing}")
    else:
        df = synthetic_dataset(args.n_per_class)

    train(df)

if __name__ == "__main__":
    main()
