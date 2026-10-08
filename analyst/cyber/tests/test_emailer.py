import sqlite3

from app.services.emailer import send_high_risk


def test_send_high_risk_accepts_sqlite_row(monkeypatch):
    monkeypatch.setenv("EMAIL_SENDER", "sender@example.com")
    monkeypatch.setenv("EMAIL_PASSWORD", "secret")
    monkeypatch.setenv("EMAIL_RECEIVER", "receiver@example.com")

    class FakeSMTP:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def login(self, sender, password):
            pass

        def send_message(self, msg):
            assert "INC-0001" in str(msg)

    monkeypatch.setattr("smtplib.SMTP_SSL", lambda *args, **kwargs: FakeSMTP())

    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute(
        "CREATE TABLE incident (id INTEGER, threat TEXT, risk_score REAL, severity INTEGER, source_ip TEXT, event_count INTEGER, ml_confidence REAL, mitre_id TEXT, mitre_name TEXT, mapping_reason TEXT, ai_summary TEXT, ai_findings TEXT, ai_recommendations TEXT)"
    )
    conn.execute(
        "INSERT INTO incident VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            1,
            "Credential stuffing",
            92,
            5,
            "10.0.0.5",
            7,
            0.98,
            "T1110",
            "Brute Force",
            "Repeated failed login attempts",
            "Summary text",
            "Findings text",
            "Recommendation text",
        ),
    )
    row = conn.execute("SELECT * FROM incident WHERE id = 1").fetchone()

    sent, message = send_high_risk(row)

    assert sent is True
    assert message == "Sent"
