"""
Generate a small labelled healthcare-application telemetry CSV.

This is for controlled project data only. It represents the application's own
normal and simulated security events and should be kept separate from public
network datasets during evaluation.
"""
from pathlib import Path
import csv, random

OUT = Path(__file__).resolve().parents[1] / "ml" / "data" / "healthcare_telemetry.csv"
OUT.parent.mkdir(parents=True, exist_ok=True)

CLASSES = [
    "Normal", "Brute Force", "Port Scan", "SQL Injection",
    "Unauthorized Access", "Privilege Escalation", "Data Exfiltration"
]

fields = [
    "src_port","dest_port","severity","is_alert","signature_length",
    "is_http","request_rate","failed_login_count","byte_count",
    "flow_duration_ms","label_id"
]

random.seed(42)
rows=[]
for label_id,label in enumerate(CLASSES):
    for _ in range(250):
        alert = int(label != "Normal")
        severity = 3 if label=="Normal" else random.choice([1,2])
        rate = random.uniform(1,4)
        failed = random.uniform(0,1)
        bytes_ = random.uniform(500,2000)
        duration = random.uniform(50,300)
        siglen = random.uniform(0,20)

        if label=="Brute Force":
            rate=random.uniform(12,30); failed=random.uniform(8,30); siglen=random.uniform(40,80)
        elif label=="Port Scan":
            rate=random.uniform(20,50); siglen=random.uniform(35,65)
        elif label=="SQL Injection":
            rate=random.uniform(5,15); bytes_=random.uniform(1200,4000); siglen=random.uniform(45,85)
        elif label=="Unauthorized Access":
            failed=random.uniform(3,10); rate=random.uniform(5,12); siglen=random.uniform(40,75)
        elif label=="Privilege Escalation":
            bytes_=random.uniform(1500,5000); siglen=random.uniform(45,80)
        elif label=="Data Exfiltration":
            bytes_=random.uniform(10000,50000); duration=random.uniform(500,3000); rate=random.uniform(8,20)

        rows.append([
            random.randint(30000,65000), 5000, severity, alert, max(0,siglen),
            1, rate, failed, bytes_, duration, label_id
        ])

with OUT.open("w", newline="", encoding="utf-8") as f:
    w=csv.writer(f); w.writerow(fields); w.writerows(rows)

print("Created:", OUT)
print("Rows:", len(rows))
