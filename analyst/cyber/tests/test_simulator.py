from app.services.simulator import generate_event


import json

from flask import Flask

from app.db import connect, init_db
from app.services.event_processor import process_event
from app.services.ml_engine import analyze
from app.services.simulator import ATTACKS, generate_event, generate_scenario


def test_normal_scenario_generates_non_alert_http_telemetry():
    event = generate_event("normal")

    assert event["event_type"] == "http"
    assert event["http"]["http_method"] == "GET"
    assert "alert" not in event


def test_each_simulator_attack_gets_its_selected_class():
    expected_classes = {
        "brute_force": "Brute Force",
        "port_scan": "Port Scan",
        "sql_injection": "SQL Injection",
        "unauthorized_access": "Unauthorized Access",
        "privilege_escalation": "Privilege Escalation",
        "data_exfiltration": "Data Exfiltration",
    }

    for scenario, expected_class in expected_classes.items():
        event = generate_event(scenario)
        assert analyze(event)[2] == expected_class


def test_every_attack_scenario_creates_a_matching_incident(tmp_path, monkeypatch):
    app = Flask(__name__)
    app.config["DB_PATH"] = tmp_path / "test.sqlite"
    init_db(app.config["DB_PATH"])
    monkeypatch.setattr("app.services.event_processor.email_configured", lambda: False)

    for index, scenario in enumerate(
        scenario for scenario in ATTACKS if scenario != "normal"
    ):
        event = generate_event(scenario)
        event["src_ip"] = f"192.168.1.{index + 20}"
        process_event(app, event)

    conn = connect(app.config["DB_PATH"])
    incident_threats = {
        row["threat"]
        for row in conn.execute("SELECT threat FROM incidents").fetchall()
    }
    conn.close()

    assert incident_threats == {
        "Brute Force",
        "Port Scan",
        "SQL Injection",
        "Unauthorized Access",
        "Privilege Escalation",
        "Data Exfiltration",
    }


def test_simulated_attack_batch_creates_one_correctly_classified_incident(
    tmp_path, monkeypatch
):
    app = Flask(__name__)
    app.config["DB_PATH"] = tmp_path / "test.sqlite"
    app.config["EVE_PATH"] = tmp_path / "eve.json"
    init_db(app.config["DB_PATH"])
    monkeypatch.setattr("app.services.event_processor.email_configured", lambda: False)

    result = generate_scenario(app, "data_exfiltration", count=10)
    generated_events = [
        json.loads(line)
        for line in app.config["EVE_PATH"].read_text(encoding="utf-8").splitlines()
    ]
    for event in generated_events:
        process_event(app, event)

    conn = connect(app.config["DB_PATH"])
    incidents = conn.execute(
        "SELECT threat, event_count FROM incidents"
    ).fetchall()
    conn.close()

    assert result == {"ok": True, "scenario": "data_exfiltration", "count": 10}
    assert len(generated_events) == 10
    assert {event["simulator_scenario"] for event in generated_events} == {
        "data_exfiltration"
    }
    assert len({event["src_ip"] for event in generated_events}) == 1
    assert [dict(incident) for incident in incidents] == [
        {"threat": "Data Exfiltration", "event_count": 10}
    ]
