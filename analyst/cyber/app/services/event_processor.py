import json, logging, threading, time
from datetime import datetime, timezone
from .ml_engine import analyze
from .mitre import map_threat
from .risk import calculate
from .ai import investigate
from .emailer import email_configured, send_high_risk
from ..db import connect
from pathlib import Path

_started=False
_lock=threading.Lock()
logger = logging.getLogger(__name__)


def _send_high_risk_email(app, incident):
    try:
        sent, message = send_high_risk(incident)
        if not sent:
            logger.warning(
                "High-risk email for incident %s was not sent: %s",
                incident["id"],
                message,
            )
            return

        conn = connect(app.config["DB_PATH"])
        try:
            conn.execute(
                "UPDATE incidents SET email_sent=1 WHERE id=?",
                (incident["id"],),
            )
            conn.commit()
        finally:
            conn.close()
    except Exception:
        logger.exception("Failed to send high-risk email for incident %s", incident["id"])

def process_event(app,e):
    score, anomaly, predicted, confidence=analyze(e)
    alert=e.get("alert",{})
    threat=predicted if predicted!="Normal" else alert.get("signature","Normal Activity")
    severity=int(alert.get("severity",3))
    mitre_id,mitre_name,reason=map_threat(predicted)
    risk=calculate(severity,anomaly,confidence)

    conn=connect(app.config["DB_PATH"])
    pending_email = None
    conn.execute("""INSERT INTO events
    (timestamp,event_type,src_ip,src_port,dest_ip,dest_port,proto,app_proto,signature,category,severity,anomaly_score,anomaly_label,predicted_class,ml_confidence,raw_json)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
    (e.get("timestamp"),e.get("event_type"),e.get("src_ip"),e.get("src_port"),e.get("dest_ip"),e.get("dest_port"),
     e.get("proto"),e.get("app_proto"),alert.get("signature"),alert.get("category"),severity,score,anomaly,predicted,confidence,json.dumps(e)))
    event_id=conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    if predicted!="Normal" or anomaly=="Anomaly":
        key=f"{predicted}:{e.get('src_ip')}:{e.get('dest_port')}"
        existing=conn.execute("SELECT * FROM incidents WHERE incident_key=?",(key,)).fetchone()
        now=datetime.now(timezone.utc).isoformat()
        if existing:
            new_count = int(existing["event_count"] or 1) + 1
            cumulative_risk = min(100, round(float(risk) + min(new_count * 2, 20), 2))
            conn.execute("""UPDATE incidents SET updated_at=?,event_count=?,
                            risk_score=?,ml_confidence=?,severity=? WHERE id=?""",
                         (now,new_count,cumulative_risk,confidence,max(severity, int(existing["severity"] or 0)),existing["id"]))
            iid=existing["id"]
        else:
            temp={
                "threat": predicted,
                "risk_score": risk,
                "source_ip": e.get("src_ip"),
                "source_port": e.get("src_port"),
                "destination_ip": e.get("dest_ip"),
                "destination_port": e.get("dest_port"),
                "protocol": e.get("proto"),
                "application_protocol": e.get("app_proto"),
                "severity": severity,
                "anomaly_score": score,
                "anomaly_label": anomaly,
                "ml_confidence": confidence,
                "signature": alert.get("signature"),
                "category": alert.get("category"),
                "mitre_id": mitre_id,
                "mitre_name": mitre_name,
                "mapping_reason": reason,
                "event_count": 1,
            }
            ai=investigate(temp)
            cur=conn.execute("""INSERT INTO incidents
            (incident_key,created_at,updated_at,threat,severity,risk_score,status,source_ip,event_count,ml_confidence,mitre_id,mitre_name,mapping_reason,ai_summary,ai_findings,ai_recommendations)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (key,now,now,predicted,severity,risk,"Open",e.get("src_ip"),1,confidence,mitre_id,mitre_name,reason,
             ai["summary"],ai["findings"],ai["recommendations"]))
            iid=cur.lastrowid
            conn.execute("INSERT INTO audit_logs(timestamp,actor,action,incident_id,details) VALUES(?,?,?,?,?)",
                         (now,"CyberAnalyst","Incident created",iid,f"{predicted}; risk={risk}"))
            row = conn.execute(
                "SELECT * FROM incidents WHERE id=?",
                (iid,)
            ).fetchone()
            if (
                row
                and not row["email_sent"]
                and email_configured()
                and (predicted != "Normal" or anomaly == "Anomaly" or risk >= 50)
            ):
                pending_email = dict(row)
    conn.commit()
    conn.close()
    if pending_email:
        threading.Thread(
            target=_send_high_risk_email,
            args=(app, pending_email),
            name=f"cyberanalyst-email-{pending_email['id']}",
            daemon=True,
        ).start()
    return event_id


def start_background_processor(app):
    global _started
    with _lock:
        if _started:
            return
        _started = True

    def worker():
        seen = 0
        last_identity = None

        while True:
            try:
                configured = app.config.get("SURICATA_EVE_PATH") if app.config.get("DETECTION_MODE") == "suricata" else app.config["EVE_PATH"]
                path = Path(configured)

                if path.exists():
                    identity = (str(path.resolve()), path.stat().st_ino, path.stat().st_size)

                    # Handle log rotation/truncation.
                    if last_identity and (
                        identity[0] != last_identity[0] or identity[2] < seen
                    ):
                        seen = 0

                    lines = path.read_text(
                        encoding="utf-8", errors="ignore"
                    ).splitlines()

                    for line in lines[seen:]:
                        if not line.strip():
                            continue
                        try:
                            process_event(app, json.loads(line))
                        except Exception as ex:
                            print("Event processing error:", ex)

                    seen = len(lines)
                    last_identity = identity

            except Exception as ex:
                print("Collector error:", ex)

            time.sleep(1)

    threading.Thread(
        target=worker,
        name="cyberanalyst-event-processor",
        daemon=True
    ).start()
