"""API REST (FastAPI) : ingestion, incidents, approbation des actions, audit."""
import hmac
import json
import logging
import os
import secrets
import time
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from . import __version__
from .config import load_config
from .engine import Engine
from .parsers import (parse_access_log, parse_auth_log, parse_firewall_log, parse_generic, parse_suricata, parse_triage_host, parse_triage_logs)

log = logging.getLogger("artex_soar")


class StatusChange(BaseModel):
    status: str
    comment: str = ""


class Decision(BaseModel):
    comment: str = ""


def create_app(cfg: Dict[str, Any] = None, engine: Engine = None, api_key: str = None) -> FastAPI:
    cfg = cfg or load_config()
    engine = engine or Engine(cfg)
    key = api_key or os.environ.get("SOAR_API_KEY")
    if not key:
        key = secrets.token_urlsafe(24)
        log.warning("SOAR_API_KEY absent : cle generee pour cette execution : %s", key)
        print(f"[SOAR] SOAR_API_KEY absent, cle temporaire : {key}", flush=True)

    app = FastAPI(title="ARTEX SOAR", version=__version__,
                  description="Reponse automatisee et strictement defensive aux campagnes ARTEX.")
    app.state.engine = engine

    def auth(x_api_key: Optional[str] = Header(default=None), x_soar_user: Optional[str] = Header(default=None)):
        if not x_api_key or not hmac.compare_digest(x_api_key, key):
            raise HTTPException(401, "cle API invalide (en-tete X-API-Key)")
        return (x_soar_user or "api")[:64]

    @app.get("/health")
    def health():
        return {"status": "ok", "version": __version__, "mode": cfg["mode"],
                "connectors": {n: {"type": c.cfg.get("type", n), "dry_run": c.effective_dry_run()}
                               for n, c in engine.connectors.items()},
                "playbooks": [p["name"] for p in engine.playbooks]}

    # -- ingestion -------------------------------------------------------------------------
    @app.post("/api/v1/ingest/access-log")
    async def ingest_access_log(request: Request, sensor: str = "web", target: Optional[str] = None,
                                user: str = Depends(auth)):
        body = (await request.body()).decode("utf-8", "replace")
        return engine.ingest(parse_access_log(body.splitlines(), sensor, target, time.time()))

    @app.post("/api/v1/ingest/auth-log")
    async def ingest_auth_log(request: Request, target: Optional[str] = None, user: str = Depends(auth)):
        body = (await request.body()).decode("utf-8", "replace")
        return engine.ingest(parse_auth_log(body.splitlines(), target, time.time()))

    @app.post("/api/v1/ingest/firewall-log")
    async def ingest_firewall_log(request: Request, target: Optional[str] = None, user: str = Depends(auth)):
        body = (await request.body()).decode("utf-8", "replace")
        return engine.ingest(parse_firewall_log(body.splitlines(), target, time.time()))

    @app.post("/api/v1/ingest/suricata")
    async def ingest_suricata(request: Request, user: str = Depends(auth)):
        body = (await request.body()).decode("utf-8", "replace").strip()
        records = json.loads(body) if body.startswith("[") else body.splitlines()
        return engine.ingest(parse_suricata(records, time.time()))

    @app.post("/api/v1/ingest/triage")
    def ingest_triage(report: Dict[str, Any], user: str = Depends(auth)):
        if "sources_suspectes" in report:
            return engine.ingest(parse_triage_logs(report, time.time()))
        return engine.ingest(parse_triage_host(report, time.time()))

    @app.post("/api/v1/events")
    def ingest_events(events: List[Dict[str, Any]], user: str = Depends(auth)):
        try:
            evs = parse_generic(events, time.time())
        except TypeError as e:
            raise HTTPException(422, str(e))
        return engine.ingest(evs)

    # -- incidents -------------------------------------------------------------------------
    @app.get("/api/v1/incidents")
    def incidents(status: Optional[str] = None, limit: int = Query(200, le=1000), user: str = Depends(auth)):
        return engine.store.list_incidents(status, limit)

    @app.get("/api/v1/incidents/{inc_id}")
    def incident(inc_id: str, user: str = Depends(auth)):
        inc = engine.store.get_incident(inc_id)
        if not inc:
            raise HTTPException(404, "incident inconnu")
        inc["actions"] = engine.store.list_actions(incident_id=inc_id)
        return inc

    @app.post("/api/v1/incidents/{inc_id}/status")
    def incident_status(inc_id: str, body: StatusChange, user: str = Depends(auth)):
        try:
            return engine.set_status(inc_id, body.status, user, body.comment)
        except KeyError:
            raise HTTPException(404, "incident inconnu")
        except ValueError as e:
            raise HTTPException(400, str(e))

    # -- actions ---------------------------------------------------------------------------
    @app.get("/api/v1/actions")
    def actions(status: Optional[str] = None, user: str = Depends(auth)):
        return engine.store.list_actions(status)

    @app.post("/api/v1/actions/{act_id}/approve")
    def approve(act_id: str, user: str = Depends(auth)):
        try:
            return engine.approve(act_id, user)
        except KeyError:
            raise HTTPException(404, "action inconnue")
        except ValueError as e:
            raise HTTPException(409, str(e))

    @app.post("/api/v1/actions/{act_id}/reject")
    def reject(act_id: str, body: Decision = Decision(), user: str = Depends(auth)):
        try:
            return engine.reject(act_id, user, body.comment)
        except KeyError:
            raise HTTPException(404, "action inconnue")
        except ValueError as e:
            raise HTTPException(409, str(e))

    @app.get("/api/v1/audit")
    def audit(limit: int = Query(200, le=2000), user: str = Depends(auth)):
        return engine.store.list_audit(limit)

    @app.get("/", response_class=HTMLResponse)
    def dashboard():
        with open(os.path.join(os.path.dirname(__file__), "dashboard.html"), encoding="utf-8") as f:
            return f.read()

    return app
