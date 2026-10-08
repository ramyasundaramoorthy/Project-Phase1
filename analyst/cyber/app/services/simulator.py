import json
import random
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[2]
EVE = ROOT / "data" / "eve.json"

ATTACKS = {
    "normal": {
        "signature": "Normal healthcare application activity",
        "category": "Normal",
        "severity": 0
    },
    "brute_force": {
        "signature": "Repeated failed login attempts",
        "category": "Attempted Administrator Privilege Gain",
        "severity": 2
    },
    "port_scan": {
        "signature": "Network service scanning activity",
        "category": "Network Scan",
        "severity": 2
    },
    "sql_injection": {
        "signature": "SQL injection pattern detected",
        "category": "Web Application Attack",
        "severity": 1
    },
    "unauthorized_access": {
        "signature": "Unauthorized administrative resource access",
        "category": "Potentially Bad Traffic",
        "severity": 2
    },
    "privilege_escalation": {
        "signature": "Privilege escalation behavior detected",
        "category": "Privilege Gain",
        "severity": 1
    },
    "data_exfiltration": {
        "signature": "Unusual outbound data transfer",
        "category": "Data Exfiltration",
        "severity": 1
    }
}

def generate_event(kind="normal"):
    if kind not in ATTACKS:
        raise ValueError(f"Unknown simulation scenario: {kind}")

    cfg = ATTACKS[kind]
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "flow_id": random.randint(10_000_000, 99_999_999),
        "simulator_scenario": kind,
        "event_type": "http" if kind == "normal" else "alert",
        "src_ip": f"192.168.1.{random.randint(20, 240)}",
        "src_port": random.randint(1024, 65535),
        "dest_ip": "127.0.0.1",
        "dest_port": 5000,
        "proto": "TCP",
        "app_proto": "http",
        "flow": {
            "pkts_toserver": random.randint(3, 50),
            "pkts_toclient": random.randint(3, 50),
            "bytes_toserver": random.randint(300, 12000),
            "bytes_toclient": random.randint(300, 20000)
        },
    }
    if kind == "normal":
        event["http"] = {
            "hostname": "localhost",
            "url": "/patients",
            "http_method": "GET",
            "status": 200,
        }
    else:
        event["alert"] = {
            "action": "allowed",
            "gid": 1,
            "signature_id": random.randint(1000000, 9999999),
            "rev": 1,
            "signature": cfg["signature"],
            "category": cfg["category"],
            "severity": cfg["severity"]
        }
    return event

def append_event(kind="normal"):
    EVE.parent.mkdir(parents=True, exist_ok=True)
    with EVE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(generate_event(kind)) + "\n")
    return kind


def generate_scenario(app, scenario="brute_force", count=10):
    if scenario not in ATTACKS:
        raise ValueError(f"Unknown simulation scenario: {scenario}")
    try:
        count = int(count)
    except (TypeError, ValueError) as exc:
        raise ValueError("Event count must be an integer") from exc
    count = max(1, min(count, 100))
    path = Path(app.config["EVE_PATH"])
    path.parent.mkdir(parents=True, exist_ok=True)
    generated = []
    source_ip = f"192.168.1.{random.randint(20, 240)}"
    with path.open("a", encoding="utf-8") as f:
        for _ in range(count):
            event = generate_event(scenario)
            event["src_ip"] = source_ip
            f.write(json.dumps(event) + "\n")
            generated.append(event)
    return {"ok": True, "scenario": scenario, "count": len(generated)}
