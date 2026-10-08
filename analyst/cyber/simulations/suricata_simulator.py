import json, random, time
from datetime import datetime, timezone
from pathlib import Path

OUT=Path(__file__).resolve().parents[1]/"data"/"eve.json"
SCENARIOS={
"normal":("Normal Healthcare Web Traffic","Normal Traffic",3),
"brute_force":("Possible Brute Force Against Healthcare Login","Attempted Administrator Privilege Gain",2),
"port_scan":("Possible Port Scan","Network Scan",2),
"sql_injection":("Suspicious SQL Injection Pattern","Web Application Attack",1),
"unauthorized_access":("Unauthorized Patient Record Access","Potentially Bad Traffic",1),
"privilege_escalation":("Possible Privilege Escalation","Privilege Escalation",1),
"data_exfiltration":("Possible Sensitive Data Transfer","Exfiltration",1)}

def make(s):
    sig,cat,sev=SCENARIOS[s]
    e={"timestamp":datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00","Z"),
       "flow_id":random.randint(10**15,10**16-1),"event_type":"http" if s=="normal" else "alert",
       "src_ip":"127.0.0.1","src_port":random.randint(40000,60000),"dest_ip":"127.0.0.1",
       "dest_port":5000,"proto":"TCP","app_proto":"http"}
    if s=="normal": e["http"]={"hostname":"localhost","url":"/patients","http_method":"GET","status":200}
    else: e["alert"]={"action":"allowed","gid":1,"signature_id":2100000,"rev":1,"signature":"CYBERANALYST "+sig,"category":cat,"severity":sev}
    return e

print("CyberAnalyst Suricata Simulator")
print("Scenarios:",", ".join(SCENARIOS))
s=input("Scenario: ").strip() or "brute_force"
n=int(input("Events [10]: ").strip() or "10")
OUT.parent.mkdir(exist_ok=True)
with OUT.open("a",encoding="utf-8") as f:
    for _ in range(n):
        f.write(json.dumps(make(s))+"\n"); f.flush(); time.sleep(.3)
print("Wrote",n,"events to",OUT)
