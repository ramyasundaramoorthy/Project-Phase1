"""
CyberAnalyst AI - Public Dataset Adapter + Evaluation

Purpose:
- Accept a CIC-IDS2017/UNSW-NB15-like CSV.
- Detect common column-name variants.
- Map labels into CyberAnalyst's threat classes where possible.
- Build the feature schema used by the live model.
- Train/evaluate XGBoost and Isolation Forest.
- Save confusion matrix and metrics.

Important:
Public network datasets are not healthcare-specific. They should be described
as network telemetry sources, while the healthcare application contributes its
own controlled application telemetry.
"""

from pathlib import Path
import argparse, json, re
import numpy as np
import pandas as pd
import joblib

from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_recall_fscore_support,
    classification_report, confusion_matrix
)
from xgboost import XGBClassifier

ROOT = Path(__file__).resolve().parents[1]
MODEL_DIR = ROOT / "ml" / "models"
REPORT_DIR = ROOT / "ml" / "reports"
MODEL_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)

CLASSES = [
    "Normal", "Brute Force", "Port Scan", "SQL Injection",
    "Unauthorized Access", "Privilege Escalation", "Data Exfiltration"
]
FEATURES = [
    "src_port", "dest_port", "severity", "is_alert", "signature_length",
    "is_http", "request_rate", "failed_login_count", "byte_count",
    "flow_duration_ms"
]

def norm(s):
    return re.sub(r"[^a-z0-9]", "", str(s).lower())

def find_col(df, names):
    normalized = {norm(c): c for c in df.columns}
    for n in names:
        if norm(n) in normalized:
            return normalized[n]
    return None

def label_map(raw):
    s = str(raw).strip().lower()
    if s in {"benign", "normal", "normal traffic"}:
        return "Normal"
    if "brute" in s or "password" in s:
        return "Brute Force"
    if "portscan" in s or "port scan" in s or "scan" in s:
        return "Port Scan"
    if "sql" in s or "injection" in s:
        return "SQL Injection"
    if "unauthorized" in s or "credential" in s or "account" in s:
        return "Unauthorized Access"
    if "privilege" in s or "escalation" in s:
        return "Privilege Escalation"
    if "exfil" in s or "infiltration" in s or "data theft" in s:
        return "Data Exfiltration"
    return None

def to_num(series, default=0):
    return pd.to_numeric(series, errors="coerce").fillna(default)

def prepare_public_csv(path):
    df = pd.read_csv(path)
    label_col = find_col(df, ["Label", "label", "Attack", "attack_cat", "Class", "class"])
    if not label_col:
        raise ValueError("Could not find a label column. Expected Label, Attack, attack_cat, Class, or class.")

    labels = df[label_col].map(label_map)
    keep = labels.notna()
    df = df.loc[keep].copy()
    labels = labels.loc[keep]

    # Common network-data column aliases.
    src_port = find_col(df, ["Source Port", "sport", "src_port", "srcport"])
    dst_port = find_col(df, ["Destination Port", "dport", "dst_port", "dstport"])
    protocol = find_col(df, ["Protocol", "proto"])
    flow_duration = find_col(df, ["Flow Duration", "dur", "duration"])
    packets = find_col(df, ["Total Fwd Packets", "Tot Fwd Pkts", "spkts", "packets"])
    bytes_col = find_col(df, ["Total Length of Fwd Packets", "TotLen Fwd Pkts", "sbytes", "bytes"])

    out = pd.DataFrame(index=df.index)
    out["src_port"] = to_num(df[src_port]) if src_port else 0
    out["dest_port"] = to_num(df[dst_port]) if dst_port else 5000
    out["severity"] = np.where(labels.eq("Normal"), 3, 2)
    out["is_alert"] = np.where(labels.eq("Normal"), 0, 1)
    out["signature_length"] = labels.astype(str).str.len()
    out["is_http"] = df[protocol].astype(str).str.lower().isin(["6", "tcp", "http"]).astype(int) if protocol else 1
    out["request_rate"] = 1.0
    out["failed_login_count"] = np.where(labels.eq("Brute Force"), 5.0, 0.0)
    out["byte_count"] = to_num(df[bytes_col], 1200) if bytes_col else 1200
    out["flow_duration_ms"] = to_num(df[flow_duration], 100) if flow_duration else 100
    out["label_id"] = labels.map({x:i for i,x in enumerate(CLASSES)})

    return out.reset_index(drop=True)

def train_and_evaluate(df):
    X = df[FEATURES]
    y = df["label_id"].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=.2, random_state=42, stratify=y
    )

    normal_train = X_train[y_train == 0]
    iso = IsolationForest(n_estimators=200, contamination=.08, random_state=42, n_jobs=-1)
    iso.fit(normal_train)

    xgb = XGBClassifier(
        n_estimators=200, max_depth=5, learning_rate=.08,
        subsample=.9, colsample_bytree=.9,
        objective="multi:softprob", num_class=len(CLASSES),
        eval_metric="mlogloss", random_state=42, n_jobs=2
    )
    xgb.fit(X_train, y_train)

    pred = xgb.predict(X_test)
    acc = float(accuracy_score(y_test, pred))
    p, r, f1, _ = precision_recall_fscore_support(
        y_test, pred, average="weighted", zero_division=0
    )
    report = classification_report(
        y_test, pred, target_names=CLASSES, output_dict=True, zero_division=0
    )
    cm = confusion_matrix(y_test, pred, labels=list(range(len(CLASSES)))).tolist()

    joblib.dump(iso, MODEL_DIR / "isolation_forest.joblib")
    joblib.dump(xgb, MODEL_DIR / "xgboost_classifier.joblib")

    metadata = {
        "trained": True,
        "source": "public_network_dataset_adapter",
        "rows_used": int(len(df)),
        "accuracy": acc,
        "weighted_precision": float(p),
        "weighted_recall": float(r),
        "weighted_f1": float(f1),
        "classes": CLASSES,
        "features": FEATURES,
        "note": "Performance depends on dataset, label mapping and class coverage. Public network datasets are not healthcare-specific."
    }
    (MODEL_DIR / "model_metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    (REPORT_DIR / "classification_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (REPORT_DIR / "confusion_matrix.json").write_text(json.dumps(cm, indent=2), encoding="utf-8")

    print(json.dumps(metadata, indent=2))
    print("\nConfusion matrix saved to:", REPORT_DIR / "confusion_matrix.json")
    print("Classification report saved to:", REPORT_DIR / "classification_report.json")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv", help="Path to CIC-IDS2017/UNSW-NB15-like CSV")
    args = ap.parse_args()
    df = prepare_public_csv(args.csv)
    if df.empty:
        raise SystemExit("No supported labels were found after mapping.")
    train_and_evaluate(df)

if __name__ == "__main__":
    main()
