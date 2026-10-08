import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS patients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    age INTEGER,
    gender TEXT,
    blood_group TEXT,
    phone TEXT,
    address TEXT,
    diagnosis TEXT,
    medication TEXT,
    doctor TEXT,
    last_visit TEXT,
    medical_notes TEXT
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    event_type TEXT,
    src_ip TEXT,
    src_port INTEGER,
    dest_ip TEXT,
    dest_port INTEGER,
    proto TEXT,
    app_proto TEXT,
    signature TEXT,
    category TEXT,
    severity INTEGER,
    anomaly_score REAL,
    anomaly_label TEXT,
    predicted_class TEXT,
    ml_confidence REAL,
    raw_json TEXT
);

CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_key TEXT UNIQUE,
    created_at TEXT,
    updated_at TEXT,
    threat TEXT,
    severity INTEGER,
    risk_score REAL,
    status TEXT DEFAULT 'Open',
    source_ip TEXT,
    event_count INTEGER DEFAULT 1,
    ml_confidence REAL DEFAULT 0,
    mitre_id TEXT,
    mitre_name TEXT,
    mapping_reason TEXT,
    ai_summary TEXT,
    ai_findings TEXT,
    ai_recommendations TEXT,
    analyst_notes TEXT,
    approved INTEGER DEFAULT 0,
    email_sent INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    actor TEXT,
    action TEXT,
    incident_id INTEGER,
    details TEXT
);
"""

def connect(db_path):
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn

def init_db(db_path):
    conn = connect(db_path)
    conn.executescript(SCHEMA)

    # Safe migration for databases created by earlier CyberAnalyst phases.
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(incidents)").fetchall()}
    if "email_sent" not in columns:
        conn.execute("ALTER TABLE incidents ADD COLUMN email_sent INTEGER DEFAULT 0")

    count = conn.execute("SELECT COUNT(*) c FROM patients").fetchone()["c"]
    if count == 0:
        patients = [
            ("P-1001","Arun Kumar",42,"Male","O+","9876543210","Pondicherry","Hypertension","Amlodipine","Dr. Priya","2026-09-10","Routine follow-up"),
            ("P-1002","Meena Devi",35,"Female","A+","9876543211","Chennai","Diabetes","Metformin","Dr. Ravi","2026-09-12","Stable"),
            ("P-1003","Rahul S",28,"Male","B+","9876543212","Bengaluru","Asthma","Salbutamol","Dr. Anitha","2026-09-14","Inhaler review"),
            ("P-1004","Kavya R",51,"Female","AB+","9876543213","Chennai","Thyroid disorder","Levothyroxine","Dr. Priya","2026-09-15","Monitoring"),
            ("P-1005","Vijay P",63,"Male","O-","9876543214","Pondicherry","Cardiac risk","Atorvastatin","Dr. Ravi","2026-09-16","Lifestyle counseling"),
            ("P-1006","Nisha K",24,"Female","B-","9876543215","Bengaluru","Migraine","Propranolol","Dr. Anitha","2026-09-17","Follow-up"),
            ("P-1007","Suresh M",47,"Male","A-","9876543216","Chennai","Gastritis","Pantoprazole","Dr. Ravi","2026-09-18","Stable"),
            ("P-1008","Divya S",31,"Female","O+","9876543217","Pondicherry","Anemia","Iron supplement","Dr. Priya","2026-09-19","Repeat CBC"),
            ("P-1009","Manoj V",56,"Male","AB-","9876543218","Bengaluru","Arthritis","NSAID","Dr. Anitha","2026-09-20","Pain review"),
            ("P-1010","Asha R",39,"Female","A+","9876543219","Chennai","PCOS","Lifestyle management","Dr. Priya","2026-09-21","Routine"),
        ]
        conn.executemany("""INSERT INTO patients
        (patient_id,name,age,gender,blood_group,phone,address,diagnosis,medication,doctor,last_visit,medical_notes)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""", patients)
    conn.commit()
    conn.close()
