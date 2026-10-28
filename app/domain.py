from copy import deepcopy
from typing import Any

EVENTS: list[dict[str, Any]] = []
ALERTS: list[dict[str, Any]] = []
for i in range(12):
    sev = ("critical", "high", "medium", "low")[i % 4]
    kind = ("ssh_bruteforce", "port_scan", "dns_anomaly", "honeypot_touch")[i % 4]
    EVENTS.append({"id": f"evt-{i+1}", "timestamp": f"2026-10-{24-i//8:02d}T12:00:00Z", "severity": sev, "kind": kind, "source": f"198.51.100.{20+i}", "summary": ("Repeated SSH failures", "Sequential connection attempts", "Unusual DNS request", "Synthetic decoy interaction")[i%4], "details": {"attempts": 12+i, "sensor": "lab-sensor-01", "network": "synthetic-lab"}})
for i in range(8):
    ALERTS.append({"id": f"alt-{i+1}", "event_id": f"evt-{i+1}", "timestamp": f"2026-10-24T{11-i:02d}:00:00Z", "severity": ("critical", "high", "medium", "low")[i%4], "status": "acknowledged" if i%3 == 0 else "open", "title": ("SSH brute force pattern", "Port sweep detected", "DNS outlier", "Decoy touched")[i%4], "description": "Synthetic alert from the isolated demo dataset."})
HONEYPOTS = [{"id":"hp-1","name":"SSH decoy","kind":"SSH simulation","status":"healthy","interactions":18},{"id":"hp-2","name":"Web decoy","kind":"HTTP simulation","status":"healthy","interactions":9},{"id":"hp-3","name":"DB decoy","kind":"SQL simulation","status":"paused","interactions":3}]
REPORTS = [{"id":"r1","title":"Weekly security summary","period":"2026-10-18 — 2026-10-24","summary":"12 synthetic events · 8 alerts · 3 simulated decoys"},{"id":"r2","title":"Decoy activity","period":"October 2026","summary":"30 simulated interactions"}]
VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
VALID_STATUSES = {"open", "acknowledged", "resolved"}

def filtered(rows: list[dict[str, Any]], query: str = "", severity: str = "", status: str = "", limit: int = 100) -> list[dict[str, Any]]:
    q = query.casefold().strip()
    result = [r for r in rows if (not q or q in " ".join(str(v) for v in r.values()).casefold()) and (not severity or r.get("severity") == severity) and (not status or r.get("status") == status)]
    return deepcopy(result[:limit])

def overview() -> dict[str, Any]:
    counts = {s: sum(1 for e in EVENTS if e["severity"] == s) for s in sorted(VALID_SEVERITIES)}
    return {"total_events": len(EVENTS), "total_alerts": len(ALERTS), "severity_counts": counts, "recent_alerts": deepcopy(ALERTS[:5]), "trend": [{"day": f"2026-10-{d:02d}", "events": d % 5 + 1} for d in range(18, 25)]}

def update_alert(alert_id: str, status: str) -> dict[str, Any] | None:
    if status not in VALID_STATUSES:
        raise ValueError("invalid status")
    for alert in ALERTS:
        if alert["id"] == alert_id:
            alert["status"] = status
            return deepcopy(alert)
    return None

def event_by_id(event_id: str) -> dict[str, Any] | None:
    row = next((e for e in EVENTS if e["id"] == event_id), None)
    return deepcopy(row) if row else None

