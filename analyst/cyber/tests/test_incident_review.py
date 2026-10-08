from pathlib import Path

import pytest
from flask import Flask

from app.db import connect, init_db
from app.routes import main


@pytest.fixture
def client(tmp_path):
    app = Flask(
        __name__,
        template_folder=str(Path(__file__).resolve().parents[1] / "app" / "templates"),
    )
    app.secret_key = "test"
    app.config.update(
        DB_PATH=tmp_path / "test.sqlite",
        EVE_PATH=tmp_path / "eve.json",
    )
    app.register_blueprint(main)
    init_db(app.config["DB_PATH"])

    with app.test_client() as test_client:
        with test_client.session_transaction() as session:
            session["admin"] = "tester"
        yield test_client


def create_incident(client):
    db_path = client.application.config["DB_PATH"]
    conn = connect(db_path)
    cursor = conn.execute(
        "INSERT INTO incidents (incident_key, threat, status, severity, risk_score) "
        "VALUES (?, ?, ?, ?, ?)",
        ("test-incident", "Brute Force", "Open", 2, 55),
    )
    incident_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return incident_id


def test_approve_marks_incident_and_shows_check(client):
    incident_id = create_incident(client)

    response = client.post(
        f"/api/incidents/{incident_id}/review",
        json={"action": "approve"},
    )

    assert response.status_code == 200
    assert response.json["incident"]["approved"] == 1
    assert response.json["incident"]["status"] == "Approved"
    page = client.get("/security/incidents")
    assert b"aria-label=\"Approved\"" in page.data
    assert b"Approved" in page.data
    detail = client.get(f"/security/incidents/{incident_id}")
    assert b"Reject and delete" in detail.data


def test_reject_deletes_incident_and_keeps_audit_record(client):
    incident_id = create_incident(client)

    response = client.post(
        f"/api/incidents/{incident_id}/review",
        json={"action": "reject"},
    )

    assert response.status_code == 200
    assert response.json == {"deleted": True, "ok": True}
    conn = connect(client.application.config["DB_PATH"])
    incident = conn.execute(
        "SELECT id FROM incidents WHERE id=?",
        (incident_id,),
    ).fetchone()
    audit = conn.execute(
        "SELECT action FROM audit_logs WHERE incident_id=?",
        (incident_id,),
    ).fetchone()
    conn.close()
    assert incident is None
    assert audit["action"] == "Analyst rejected and deleted incident"


def test_unknown_simulation_scenario_returns_client_error(client):
    response = client.post(
        "/api/simulate",
        json={"scenario": "not-a-scenario", "count": 1},
    )

    assert response.status_code == 400
    assert response.json["ok"] is False


def test_simulator_api_writes_requested_telemetry(client):
    response = client.post(
        "/api/simulate",
        json={"scenario": "brute_force", "count": 2},
    )

    assert response.status_code == 200
    assert response.json == {"count": 2, "ok": True, "scenario": "brute_force"}
    lines = client.application.config["EVE_PATH"].read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
