from flask import Blueprint, render_template, request, redirect, url_for, session, jsonify, current_app
from functools import wraps
from datetime import datetime
import os, json
from .db import connect, init_db
from .services.suricata import status as suricata_status, read_events
from .services.coverage import calculate_coverage

main = Blueprint("main", __name__)

@main.before_app_request
def setup():
    init_db(current_app.config["DB_PATH"])

def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if not session.get("admin"):
            return redirect(url_for("main.login"))
        return fn(*a, **kw)
    return wrapper

@main.route("/", methods=["GET","POST"])
def login():
    if request.method == "POST":
        u = request.form.get("username","")
        p = request.form.get("password","")
        if u == os.getenv("ADMIN_USERNAME","admin") and p == os.getenv("ADMIN_PASSWORD","admin@123"):
            session["admin"] = u
            return redirect(url_for("main.patients"))
        return render_template("login.html", error="Invalid administrator credentials")
    return render_template("login.html")

@main.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("main.login"))

@main.route("/patients")
@login_required
def patients():
    q = request.args.get("q","").strip()
    conn = connect(current_app.config["DB_PATH"])
    if q:
        rows = conn.execute("""SELECT * FROM patients WHERE patient_id LIKE ? OR name LIKE ? OR diagnosis LIKE ?
                               ORDER BY id DESC""",(f"%{q}%",f"%{q}%",f"%{q}%")).fetchall()
    else:
        rows = conn.execute("SELECT * FROM patients ORDER BY id DESC").fetchall()
    conn.close()
    return render_template("patients.html", patients=rows, q=q)

@main.route("/patients/new", methods=["GET","POST"])
@login_required
def patient_new():
    if request.method == "POST":
        data = [request.form.get(x,"") for x in ["patient_id","name","age","gender","blood_group","phone","address","diagnosis","medication","doctor","last_visit","medical_notes"]]
        conn=connect(current_app.config["DB_PATH"])
        conn.execute("""INSERT INTO patients
        (patient_id,name,age,gender,blood_group,phone,address,diagnosis,medication,doctor,last_visit,medical_notes)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""", data)
        conn.commit(); conn.close()
        return redirect(url_for("main.patients"))
    return render_template("patient_form.html", patient=None, title="Add Patient")

@main.route("/patients/<int:pid>")
@login_required
def patient_detail(pid):
    conn=connect(current_app.config["DB_PATH"])
    p=conn.execute("SELECT * FROM patients WHERE id=?",(pid,)).fetchone()
    conn.close()
    return render_template("patient_detail.html", patient=p)

@main.route("/patients/<int:pid>/edit", methods=["GET","POST"])
@login_required
def patient_edit(pid):
    conn=connect(current_app.config["DB_PATH"])
    if request.method=="POST":
        vals=[request.form.get(x,"") for x in ["patient_id","name","age","gender","blood_group","phone","address","diagnosis","medication","doctor","last_visit","medical_notes"]]
        vals.append(pid)
        conn.execute("""UPDATE patients SET patient_id=?,name=?,age=?,gender=?,blood_group=?,phone=?,address=?,
        diagnosis=?,medication=?,doctor=?,last_visit=?,medical_notes=? WHERE id=?""",vals)
        conn.commit(); conn.close()
        return redirect(url_for("main.patient_detail",pid=pid))
    p=conn.execute("SELECT * FROM patients WHERE id=?",(pid,)).fetchone(); conn.close()
    return render_template("patient_form.html", patient=p, title="Modify Patient")

@main.route("/patients/<int:pid>/delete", methods=["POST"])
@login_required
def patient_delete(pid):
    conn=connect(current_app.config["DB_PATH"]); conn.execute("DELETE FROM patients WHERE id=?",(pid,)); conn.commit(); conn.close()
    return redirect(url_for("main.patients"))

@main.route("/security")
@login_required
def security():
    return render_template("security.html")

@main.route("/security/incidents")
@login_required
def incidents():
    conn=connect(current_app.config["DB_PATH"])
    rows=conn.execute("SELECT * FROM incidents ORDER BY id DESC").fetchall()
    conn.close()
    return render_template("incidents.html", incidents=rows)

@main.route("/security/incidents/<int:incident_id>")
@login_required
def incident_detail(incident_id):
    conn=connect(current_app.config["DB_PATH"])
    incident=conn.execute("SELECT * FROM incidents WHERE id=?",(incident_id,)).fetchone()
    events=conn.execute("""SELECT * FROM events WHERE src_ip=? ORDER BY id DESC LIMIT 50""",
                        (incident["source_ip"],)).fetchall() if incident else []
    conn.close()
    return render_template("incident_detail.html", incident=incident, events=events)

@main.route("/api/ml-metadata")
@login_required
def ml_metadata():
    import json
    p = current_app.config["BASE_DIR"] / "ml" / "models" / "model_metadata.json"
    if not p.exists():
        return jsonify({"trained": False, "message": "Run python ml/train_models.py first."})
    return jsonify({"trained": True, **json.loads(p.read_text(encoding="utf-8"))})

@main.route("/security/ml")
@login_required
def ml_analysis():
    conn=connect(current_app.config["DB_PATH"]); rows=conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT 30").fetchall(); conn.close()
    return render_template("ml.html", events=rows)

@main.route("/security/mitre")
@login_required
def mitre():
    conn=connect(current_app.config["DB_PATH"]); rows=conn.execute("SELECT * FROM incidents ORDER BY id DESC").fetchall(); conn.close()
    return render_template("mitre.html", incidents=rows)

@main.route("/security/coverage")
@login_required
def coverage():
    return render_template("coverage.html")

@main.route("/security/ai")
@login_required
def ai():
    conn=connect(current_app.config["DB_PATH"]); rows=conn.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT 20").fetchall(); conn.close()
    return render_template("ai.html", incidents=rows)


@main.route("/api/incidents/<int:incident_id>/review", methods=["POST"])
@login_required
def incident_review(incident_id):
    data = request.get_json(silent=True) or {}
    action = data.get("action")
    if action not in {"approve", "reject", "close", "edit"}:
        return jsonify({"ok": False, "error": "action must be approve, reject, close or edit"}), 400

    conn = connect(current_app.config["DB_PATH"])
    incident = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
    if not incident:
        conn.close()
        return jsonify({"ok": False, "error": "Incident not found"}), 404

    now = datetime.utcnow().isoformat()
    if action == "approve":
        conn.execute("UPDATE incidents SET approved=1, status='Approved', updated_at=? WHERE id=?", (now, incident_id))
        detail = "Analyst approved incident"
    elif action == "reject":
        conn.execute("DELETE FROM incidents WHERE id=?", (incident_id,))
        detail = "Analyst rejected and deleted incident"
    elif action == "close":
        conn.execute("UPDATE incidents SET status='Closed', updated_at=? WHERE id=?", (now, incident_id))
        detail = "Analyst closed incident"
    else:
        notes = str(data.get("analyst_notes", ""))[:2000]
        conn.execute("UPDATE incidents SET analyst_notes=?, updated_at=? WHERE id=?", (notes, now, incident_id))
        detail = "Analyst edited incident notes"

    conn.execute(
        "INSERT INTO audit_logs(timestamp,actor,action,incident_id,details) VALUES(?,?,?,?,?)",
        (now, session.get("admin","admin"), detail, incident_id, str(data)[:2000])
    )
    conn.commit()
    if action == "reject":
        conn.close()
        return jsonify({"ok": True, "deleted": True})

    updated = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
    conn.close()
    return jsonify({"ok": True, "incident": dict(updated)})

@main.route("/security/audit")
@login_required
def audit():
    conn=connect(current_app.config["DB_PATH"]); rows=conn.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 100").fetchall(); conn.close()
    return render_template("audit.html", logs=rows)

@main.route("/security/simulator")
@login_required
def simulator():
    return render_template("simulator.html")

@main.route("/api/stats")
@login_required
def stats():
    conn=connect(current_app.config["DB_PATH"])
    out={}
    for key,sql in {
        "events":"SELECT COUNT(*) c FROM events",
        "anomalies":"SELECT COUNT(*) c FROM events WHERE anomaly_label='Anomaly'",
        "incidents":"SELECT COUNT(*) c FROM incidents",
        "high_risk":"SELECT COUNT(*) c FROM incidents WHERE risk_score>=70",
    }.items():
        out[key]=conn.execute(sql).fetchone()["c"]
    out["open_incidents"]=conn.execute("SELECT COUNT(*) c FROM incidents WHERE status='Open'").fetchone()["c"]
    recent=conn.execute("""SELECT timestamp,event_type,src_ip,signature,severity,predicted_class,ml_confidence
                           FROM events ORDER BY id DESC LIMIT 12""").fetchall()
    out["recent"]=[dict(x) for x in recent]
    conn.close()
    return jsonify(out)

@main.route("/api/simulate", methods=["POST"])
@login_required
def api_simulate():
    from .services.simulator import generate_scenario
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"ok": False, "error": "A JSON request body is required"}), 400
    try:
        result = generate_scenario(
            current_app,
            data.get("scenario", "brute_force"),
            data.get("count", 10),
        )
    except (TypeError, ValueError) as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    return jsonify(result)

@main.route("/api/detection-status")
@login_required
def api_detection_status():
    mode = current_app.config.get("DETECTION_MODE", "demo")
    result = suricata_status()
    result["mode"] = mode
    if mode == "suricata":
        result["recent_events"] = len(read_events(max_events=25))
    return jsonify(result)


@main.route("/security/suricata")
@login_required
def suricata_page():
    return render_template("suricata.html")

@main.route("/api/coverage")
@login_required
def api_coverage():
    conn = connect(current_app.config["DB_PATH"])
    rows = conn.execute(
        "SELECT threat, mitre_id, mitre_name FROM incidents ORDER BY id DESC"
    ).fetchall()
    conn.close()
    incidents = [
        {"threat": x["threat"], "mitre_id": x["mitre_id"], "mitre_name": x["mitre_name"]}
        for x in rows
    ]
    return jsonify(calculate_coverage(incidents))

@main.route("/api/live-events")
@login_required
def api_live_events():
    conn = connect(current_app.config["DB_PATH"])
    rows = conn.execute(
        "SELECT timestamp,src_ip,src_port,dest_ip,dest_port,proto,signature,severity,predicted_class,ml_confidence,anomaly_label FROM events ORDER BY id DESC LIMIT 30"
    ).fetchall()
    conn.close()
    return jsonify({"events": [dict(x) for x in rows]})

@main.route("/security/events")
@login_required
def events_page():
    return render_template("events.html")

@main.route("/security/coverage")
@login_required
def coverage_page():
    return render_template("coverage.html")

@main.route("/api/incidents/<int:incident_id>/email", methods=["POST"])
@login_required
def resend_incident_email(incident_id):
    from .services.emailer import send_high_risk

    conn = connect(current_app.config["DB_PATH"])
    incident = conn.execute(
        "SELECT * FROM incidents WHERE id=?", (incident_id,)
    ).fetchone()

    if not incident:
        conn.close()
        return jsonify({"ok": False, "error": "Incident not found"}), 404

    try:
        sent, message = send_high_risk(incident)
        if sent:
            conn.execute(
                "UPDATE incidents SET email_sent=1 WHERE id=?",
                (incident_id,)
            )
            conn.execute(
                "INSERT INTO audit_logs(timestamp,actor,action,incident_id,details) "
                "VALUES(?,?,?,?,?)",
                (
                    datetime.utcnow().isoformat(),
                    session.get("admin", "admin"),
                    "High-risk email sent",
                    incident_id,
                    "Manual analyst email notification"
                )
            )
            conn.commit()
        conn.close()
        return jsonify({"ok": sent, "message": message})
    except Exception as exc:
        conn.close()
        return jsonify({"ok": False, "error": str(exc)}), 500

@main.route("/api/ml-evaluation")
@login_required
def ml_evaluation_report():
    path = current_app.config["BASE_DIR"] / "ml" / "reports" / "evaluation_report.json"
    if not path.exists():
        return jsonify({
            "available": False,
            "message": "Run python ml/evaluate_models.py after training."
        })
    return jsonify({"available": True, **json.loads(path.read_text(encoding="utf-8"))})

@main.route("/health")
def health():
    return jsonify({"status": "ok", "service": "CyberAnalyst AI"})
