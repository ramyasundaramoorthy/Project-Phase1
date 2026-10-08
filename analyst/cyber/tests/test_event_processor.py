import threading
import time

from flask import Flask

from app.db import connect, init_db
from app.services import event_processor
from app.services.simulator import generate_event


def test_email_delivery_does_not_block_event_processing(tmp_path, monkeypatch):
    app = Flask(__name__)
    app.config["DB_PATH"] = tmp_path / "test.sqlite"
    init_db(app.config["DB_PATH"])

    monkeypatch.setattr(
        event_processor,
        "analyze",
        lambda event: (-0.5, "Anomaly", "Brute Force", 0.95),
    )
    monkeypatch.setattr(event_processor, "email_configured", lambda: True)
    email_started = threading.Event()
    release_email = threading.Event()

    def delayed_email(incident):
        email_started.set()
        assert release_email.wait(timeout=5)
        return True, "Sent"

    monkeypatch.setattr(event_processor, "send_high_risk", delayed_email)

    completed = threading.Event()
    result = []

    def process():
        result.append(event_processor.process_event(app, generate_event("brute_force")))
        completed.set()

    processing_thread = threading.Thread(target=process)
    processing_thread.start()

    try:
        assert email_started.wait(timeout=2)
        assert completed.wait(timeout=1)
        conn = connect(app.config["DB_PATH"])
        assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0] == 1
        conn.close()
    finally:
        release_email.set()
        processing_thread.join(timeout=2)

    assert not processing_thread.is_alive()
    assert result == [1]

    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        conn = connect(app.config["DB_PATH"])
        email_sent = conn.execute(
            "SELECT email_sent FROM incidents"
        ).fetchone()["email_sent"]
        conn.close()
        if email_sent:
            break
        time.sleep(0.01)
    assert email_sent == 1
