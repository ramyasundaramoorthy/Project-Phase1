"""Evaluate the saved CyberAnalyst models on a held-out controlled dataset."""
from pathlib import Path
import json
import joblib
import numpy as np
import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    classification_report,
    confusion_matrix,
)

ROOT = Path(__file__).resolve().parents[1]
MODEL_DIR = ROOT / "ml" / "models"
REPORT_DIR = ROOT / "ml" / "reports"
REPORT_DIR.mkdir(parents=True, exist_ok=True)

from train_models import FEATURES, CLASSES, synthetic_dataset

def main():
    xgb_path = MODEL_DIR / "xgboost_classifier.joblib"
    iso_path = MODEL_DIR / "isolation_forest.joblib"

    if not xgb_path.exists() or not iso_path.exists():
        raise SystemExit("Models not found. Run: python ml/train_models.py")

    df = synthetic_dataset(n_per_class=150, seed=2026)
    X = df[FEATURES]
    y = df["label_id"].astype(int)

    xgb = joblib.load(xgb_path)
    iso = joblib.load(iso_path)

    pred = xgb.predict(X).astype(int)

    accuracy = float(accuracy_score(y, pred))
    precision, recall, f1, _ = precision_recall_fscore_support(
        y, pred, average="weighted", zero_division=0
    )

    # Isolation Forest is evaluated as a binary normal-vs-anomaly detector.
    iso_actual = (y != 0).astype(int)
    iso_pred = (iso.predict(X) == -1).astype(int)

    iso_precision, iso_recall, iso_f1, _ = precision_recall_fscore_support(
        iso_actual, iso_pred, average="binary", zero_division=0
    )

    result = {
        "evaluation_source": "controlled held-out synthetic telemetry",
        "rows": int(len(df)),
        "xgboost": {
            "accuracy": accuracy,
            "weighted_precision": float(precision),
            "weighted_recall": float(recall),
            "weighted_f1": float(f1),
            "classification_report": classification_report(
                y, pred, target_names=CLASSES, output_dict=True, zero_division=0
            ),
            "confusion_matrix": confusion_matrix(y, pred).tolist(),
        },
        "isolation_forest": {
            "binary_normal_vs_anomaly_precision": float(iso_precision),
            "binary_normal_vs_anomaly_recall": float(iso_recall),
            "binary_normal_vs_anomaly_f1": float(iso_f1),
            "confusion_matrix": confusion_matrix(iso_actual, iso_pred).tolist(),
        },
        "warning": (
            "These metrics describe the controlled synthetic evaluation set "
            "and must not be presented as real-world production performance."
        )
    }

    (REPORT_DIR / "evaluation_report.json").write_text(
        json.dumps(result, indent=2), encoding="utf-8"
    )

    print(json.dumps({
        "rows": result["rows"],
        "xgboost": result["xgboost"],
        "isolation_forest": result["isolation_forest"]
    }, indent=2))

if __name__ == "__main__":
    main()
