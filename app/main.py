import hmac
import os
from typing import Literal
from fastapi import Depends, FastAPI, Header, HTTPException, Query
from pydantic import BaseModel, Field
from . import domain

app = FastAPI(title="NeuroSnare Development API", version="0.1.0", docs_url="/docs")
DEMO_USER = "analyst"
DEMO_PASSWORD = "demo-only-change-me"
TOKEN = os.getenv("NEUROSNARE_DEMO_TOKEN", "demo-only-change-me")

class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=200)
class AlertUpdate(BaseModel):
    status: Literal["open", "acknowledged", "resolved"]

def require_auth(authorization: str | None = Header(default=None)) -> None:
    expected = "Bearer " + TOKEN
    if not authorization or not hmac.compare_digest(authorization, expected):
        raise HTTPException(status_code=401, detail="Authentication required")

@app.get("/api/v1/health")
def health():
    return {"status": "ok", "mode": "development-mock"}

@app.post("/api/v1/auth/login")
def login(body: LoginRequest):
    if not (hmac.compare_digest(body.username, DEMO_USER) and hmac.compare_digest(body.password, DEMO_PASSWORD)):
        raise HTTPException(status_code=401, detail="Invalid demo credentials")
    return {"access_token": TOKEN, "token_type": "bearer"}

@app.get("/api/v1/overview", dependencies=[Depends(require_auth)])
def get_overview():
    return domain.overview()

@app.get("/api/v1/events", dependencies=[Depends(require_auth)])
def get_events(query: str = Query(default="", max_length=100), severity: str = Query(default=""), limit: int = Query(default=100, ge=1, le=500)):
    if severity and severity not in domain.VALID_SEVERITIES:
        raise HTTPException(status_code=422, detail="Invalid severity")
    return domain.filtered(domain.EVENTS, query=query, severity=severity, limit=limit)

@app.get("/api/v1/events/{event_id}", dependencies=[Depends(require_auth)])
def get_event(event_id: str):
    row = domain.event_by_id(event_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Event not found")
    return row

@app.get("/api/v1/alerts", dependencies=[Depends(require_auth)])
def get_alerts(query: str = Query(default="", max_length=100), severity: str = Query(default=""), status: str = Query(default="")):
    if severity and severity not in domain.VALID_SEVERITIES:
        raise HTTPException(status_code=422, detail="Invalid severity")
    if status and status not in domain.VALID_STATUSES:
        raise HTTPException(status_code=422, detail="Invalid status")
    return domain.filtered(domain.ALERTS, query=query, severity=severity, status=status)

@app.patch("/api/v1/alerts/{alert_id}", dependencies=[Depends(require_auth)])
def patch_alert(alert_id: str, body: AlertUpdate):
    row = domain.update_alert(alert_id, body.status)
    if row is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return row

@app.get("/api/v1/honeypots", dependencies=[Depends(require_auth)])
def get_honeypots():
    return domain.HONEYPOTS

@app.get("/api/v1/reports", dependencies=[Depends(require_auth)])
def get_reports():
    return domain.REPORTS
