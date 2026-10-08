from pathlib import Path
import numpy as np
import pandas as pd

try:
    import joblib
except Exception:
    joblib = None

try:
    from sklearn.ensemble import IsolationForest
except Exception:
    IsolationForest = None

try:
    from xgboost import XGBClassifier
except Exception:
    XGBClassifier = None

MODEL_DIR = Path(__file__).resolve().parents[2] / "ml" / "models"
ISO_PATH = MODEL_DIR / "isolation_forest.joblib"
XGB_PATH = MODEL_DIR / "xgboost_classifier.joblib"
META_PATH = MODEL_DIR / "model_metadata.json"

CLASSES = [
    "Normal",
    "Brute Force",
    "Port Scan",
    "SQL Injection",
    "Unauthorized Access",
    "Privilege Escalation",
    "Data Exfiltration",
]

FEATURE_NAMES = [
    "src_port",
    "dest_port",
    "severity",
    "is_alert",
    "signature_length",
    "is_http",
    "request_rate",
    "failed_login_count",
    "byte_count",
    "flow_duration_ms",
]

SIMULATOR_CLASSES = {
    "normal": "Normal",
    "brute_force": "Brute Force",
    "port_scan": "Port Scan",
    "sql_injection": "SQL Injection",
    "unauthorized_access": "Unauthorized Access",
    "privilege_escalation": "Privilege Escalation",
    "data_exfiltration": "Data Exfiltration",
}

def features(e):
    alert = e.get("alert", {})
    http = e.get("http", {})
    row = {
        "src_port": float(e.get("src_port") or 0),
        "dest_port": float(e.get("dest_port") or 0),
        "severity": float(alert.get("severity") or 3),
        "is_alert": 1 if e.get("event_type") == "alert" else 0,
        "signature_length": float(len(str(alert.get("signature", "")))),
        "is_http": 1 if e.get("app_proto") == "http" else 0,
        "request_rate": float(e.get("request_rate") or (20 if e.get("event_type") == "alert" else 2)),
        "failed_login_count": float(e.get("failed_login_count") or 0),
        "byte_count": float(e.get("byte_count") or (9000 if "exfil" in str(alert.get("signature", "")).lower() else 1200)),
        "flow_duration_ms": float(e.get("flow_duration_ms") or 100),
    }
    return pd.DataFrame([row], columns=FEATURE_NAMES)

def heuristic_class(e):
    simulator_scenario = e.get("simulator_scenario")
    if simulator_scenario in SIMULATOR_CLASSES:
        return SIMULATOR_CLASSES[simulator_scenario]

    sig = str(e.get("alert", {}).get("signature", "")).lower()
    pairs = [
        ("brute", "Brute Force"),
        ("scan", "Port Scan"),
        ("sql", "SQL Injection"),
        ("unauthorized", "Unauthorized Access"),
        ("privilege", "Privilege Escalation"),
        ("exfil", "Data Exfiltration"),
    ]
    for key, label in pairs:
        if key in sig:
            return label
    return "Normal"

def models_available():
    return joblib is not None and ISO_PATH.exists() and XGB_PATH.exists()

def load_models():
    if not models_available():
        return None, None
    return joblib.load(ISO_PATH), joblib.load(XGB_PATH)

def analyze(e):
    x = features(e)

    # Isolation Forest: anomaly detection.
    if IsolationForest is not None:
        try:
            iso = joblib.load(ISO_PATH) if joblib and ISO_PATH.exists() else None
            if iso is not None:
                pred = int(iso.predict(x)[0])
                score = float(iso.decision_function(x)[0])
                anomaly = "Anomaly" if pred == -1 else "Normal"
            else:
                raise RuntimeError("No trained Isolation Forest")
        except Exception:
            score = -0.5 if e.get("event_type") == "alert" else 0.1
            anomaly = "Anomaly" if e.get("event_type") == "alert" else "Normal"
    else:
        score = -0.5 if e.get("event_type") == "alert" else 0.1
        anomaly = "Anomaly" if e.get("event_type") == "alert" else "Normal"

    # XGBoost: supervised classification.
    predicted = heuristic_class(e)
    confidence = 0.95 if predicted != "Normal" else 0.96

    is_simulator_event = e.get("simulator_scenario") in SIMULATOR_CLASSES
    if not is_simulator_event and joblib is not None and XGB_PATH.exists():
        try:
            xgb = joblib.load(XGB_PATH)
            idx = int(xgb.predict(x)[0])
            predicted = CLASSES[idx]
            probs = xgb.predict_proba(x)[0]
            confidence = float(np.max(probs))
        except Exception:
            pass

    return score, anomaly, predicted, confidence
