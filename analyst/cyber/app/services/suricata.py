import json
import os
from pathlib import Path

def eve_path():
    return Path(os.getenv("SURICATA_EVE_PATH", "data/eve.json"))

def read_events(path=None, max_events=100):
    path = Path(path or eve_path())
    if not path.exists():
        return []

    events = []
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()[-max_events:]
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
            if isinstance(event, dict):
                events.append(normalize_event(event))
        except json.JSONDecodeError:
            continue
    return events

def normalize_event(event):
    alert = event.get("alert") or {}
    flow = event.get("flow") or {}

    return {
        "timestamp": event.get("timestamp"),
        "flow_id": event.get("flow_id"),
        "event_type": event.get("event_type", "unknown"),
        "src_ip": event.get("src_ip"),
        "src_port": event.get("src_port"),
        "dest_ip": event.get("dest_ip"),
        "dest_port": event.get("dest_port"),
        "proto": event.get("proto"),
        "app_proto": event.get("app_proto"),
        "flow_duration_ms": flow.get("age") or flow.get("duration"),
        "packet_count": (flow.get("pkts_toserver") or 0) + (flow.get("pkts_toclient") or 0),
        "byte_count": (flow.get("bytes_toserver") or 0) + (flow.get("bytes_toclient") or 0),
        "alert": {
            "action": alert.get("action"),
            "gid": alert.get("gid"),
            "signature_id": alert.get("signature_id"),
            "rev": alert.get("rev"),
            "signature": alert.get("signature"),
            "category": alert.get("category"),
            "severity": alert.get("severity")
        }
    }

def status(path=None):
    path = Path(path or eve_path())
    return {
        "mode": "suricata",
        "eve_path": str(path),
        "exists": path.exists(),
        "size_bytes": path.stat().st_size if path.exists() else 0
    }
