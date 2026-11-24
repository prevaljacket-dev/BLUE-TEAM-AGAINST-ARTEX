"""Moteur SOAR : correlation des evenements en incidents, puis execution des playbooks."""
import threading
import time
import uuid
from typing import Any, Dict, Iterable, List, Optional

from .connectors import build_connectors
from .detection import TrackerPool, analyse_event
from .guard import Guard
from .models import SEVERITIES, Event, sev_rank
from .signatures import STAGES
from .store import Store

CLOSED = ("closed", "false_positive")


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


class Engine:
    def __init__(self, cfg: Dict[str, Any], store: Optional[Store] = None):
        self.cfg = cfg
        self.store = store or Store(cfg["database"])
        self.connectors = build_connectors(cfg)
        self.guard = Guard(cfg, self.store)
        det = cfg["detection"]
        self.min_score = int(det["min_score"])
        self.burst = int(det["burst_threshold"])
        self.timeout = float(det["incident_timeout"])
        self.pool = TrackerPool(int(det["max_tracked_sources"]))
        self.playbooks = cfg.get("playbooks") or []
        self._lock = threading.RLock()
        self._validate_playbooks()

    def _validate_playbooks(self):
        for pb in self.playbooks:
            for act in pb.get("actions", []):
                name = act.get("connector")
                if name not in self.connectors:
                    raise ValueError(f"playbook {pb.get('name')}: connecteur inconnu {name!r}")
                if act["type"] not in self.connectors[name].supports:
                    raise ValueError(f"playbook {pb.get('name')}: {name} ne sait pas faire {act['type']}")

    # ------------------------------------------------------------------------------------
    # Correlation
    # ------------------------------------------------------------------------------------
    def _candidate(self, key: str, ev: Event, tracker) -> Dict[str, Any]:
        inc = getattr(tracker, "incident", None)
        if inc is None:
            stored = self.store.latest_incident(key)
            if stored and stored["status"] not in CLOSED and ev.ts - stored["last_seen"] <= self.timeout:
                inc = stored
        if inc is not None and (inc["status"] in CLOSED or ev.ts - inc["last_seen"] > self.timeout):
            self.pool.reset(key)
            tracker = self.pool.get(key)
            tracker.update(ev)
            inc = None
        if inc is None:
            inc = {
                "id": None, "key": key, "kind": "host" if key.startswith("host:") else "source",
                "source_ip": None if key.startswith("host:") else key, "targets": [], "status": "open",
                "severity": "P3", "stage": "recon", "score": 0, "artex_confirmed": False,
                "engagement": None, "first_seen": ev.ts, "last_seen": ev.ts, "events": 0,
                "indicators": {}, "techniques": [], "successful": [], "samples": [], "fired": [],
                "history": [],
            }
        tracker.incident = inc
        return inc

    def _apply(self, inc: Dict[str, Any], ev: Event, findings) -> None:
        inc["events"] += 1
        inc["last_seen"] = max(inc["last_seen"], ev.ts)
        inc["first_seen"] = min(inc["first_seen"], ev.ts)
        if ev.target and ev.target not in inc["targets"] and len(inc["targets"]) < 50:
            inc["targets"].append(ev.target)
        sampled = False
        for f in findings:
            if f.label not in inc["indicators"]:
                inc["score"] += f.weight
                inc["indicators"][f.label] = 0
            inc["indicators"][f.label] += 1
            if f.technique not in inc["techniques"]:
                inc["techniques"].append(f.technique)
            if STAGES.index(f.stage) > STAGES.index(inc["stage"]):
                inc["stage"] = f.stage
            if f.success and f.label not in inc["successful"]:
                inc["successful"].append(f.label)
            inc["artex_confirmed"] |= f.artex
            if f.engagement:
                inc["engagement"] = f.engagement
            if not sampled and ev.raw and len(inc["samples"]) < 20 and not f.label.startswith(("Rafale", "Enumeration", "Rotation", "Chemins", "Brute")):
                inc["samples"].append(ev.raw[:500])
                sampled = True
        inc["severity"] = SEVERITIES[max(sev_rank(inc["severity"]), sev_rank(self._severity(inc)))]
        if inc["severity"] == "P1":
            inc["stage"] = "execution"

    @staticmethod
    def _severity(inc) -> str:
        """Qualification du playbook : P3 recon, P2 exploitation/identifiants, P1 compromission."""
        succ = inc["successful"]
        if inc["stage"] == "execution" or any("php2shell" in s and "session" in s for s in succ):
            return "P1"
        if inc["stage"] == "credential_access" or any("Charge" in s or "IDS" in s for s in succ):
            return "P2"
        return "P3"

    def _escalate_targets(self, host: str, changed: Dict[str, Dict[str, Any]]):
        """Un IOC sur un serveur rend P1 les sources qui l'ont attaque recemment."""
        for inc in self.store.list_incidents(status="open") + self.store.list_incidents(status="authorized"):
            if inc["kind"] == "source" and host in inc["targets"] and inc["severity"] != "P1":
                inc = self._live(changed.get(inc["id"], inc))
                label = f"Compromission constatee sur {host}"
                inc["indicators"][label] = 1
                inc["successful"].append(label)
                inc["stage"] = "execution"
                inc["severity"] = "P1"
                self._persist(inc)
                changed[inc["id"]] = inc

    def _live(self, inc):
        """Retourne l'objet incident tenu en memoire par le moteur (s'il existe)."""
        tracker = self.pool._items.get(inc["key"])
        live = getattr(tracker, "incident", None) if tracker is not None else None
        return live if live is not None and live.get("id") == inc["id"] else inc

    def _persist(self, inc):
        if inc["id"] is None:
            inc["id"] = _new_id("INC")
            inc["created"] = time.time()
            self.store.audit("engine", "incident_created", {"id": inc["id"], "key": inc["key"]})
        if inc["status"] == "open" and self.guard.is_authorized(inc.get("source_ip"), inc.get("engagement")):
            inc["status"] = "authorized"
            self.store.audit("engine", "incident_authorized", {"id": inc["id"], "engagement": inc.get("engagement")})
        self.store.save_incident(inc)

    # ------------------------------------------------------------------------------------
    # Entree principale
    # ------------------------------------------------------------------------------------
    def ingest(self, events: Iterable[Event]) -> Dict[str, Any]:
        with self._lock:
            n = 0
            changed: Dict[str, Dict[str, Any]] = {}
            for ev in events:
                n += 1
                key = f"host:{ev.target}" if ev.kind == "host" else ev.source_ip
                if not key:
                    continue
                tracker = self.pool.get(key)
                tracker.update(ev)
                findings = analyse_event(ev) + tracker.behaviour(self.burst)
                inc = self._candidate(key, ev, tracker)
                before = (inc["score"], inc["severity"], inc["stage"])
                self._apply(inc, ev, findings)
                if inc["score"] < self.min_score and inc["id"] is None:
                    continue
                if inc["id"] is None or before != (inc["score"], inc["severity"], inc["stage"]):
                    self._persist(inc)
                    changed[inc["id"]] = inc
                elif inc["events"] % 50 == 0:
                    self.store.save_incident(inc)
                if ev.kind == "host" and ev.target:
                    self._escalate_targets(ev.target, changed)
            actions = []
            for inc in changed.values():
                self.store.save_incident(inc)
                actions += self.run_playbooks(inc)
            return {"events": n, "incidents": list(changed), "actions": [a["id"] for a in actions]}

    # ------------------------------------------------------------------------------------
    # Playbooks
    # ------------------------------------------------------------------------------------
    @staticmethod
    def _matches(when: Dict[str, Any], inc: Dict[str, Any]) -> bool:
        if inc["status"] in CLOSED:
            return False
        if inc["status"] == "authorized" and not when.get("include_authorized", False):
            return False
        if when.get("only_authorized") and inc["status"] != "authorized":
            return False
        if "min_severity" in when and sev_rank(inc["severity"]) < sev_rank(when["min_severity"]):
            return False
        if inc["score"] < int(when.get("min_score", 0)):
            return False
        if "stages" in when and inc["stage"] not in when["stages"]:
            return False
        if "artex_confirmed" in when and bool(when["artex_confirmed"]) != inc["artex_confirmed"]:
            return False
        if "kind" in when and when["kind"] != inc["kind"]:
            return False
        return True

    def run_playbooks(self, inc: Dict[str, Any]) -> List[Dict[str, Any]]:
        created = []
        for pb in self.playbooks:
            if not self._matches(pb.get("when", {}), inc):
                continue
            for i, spec in enumerate(pb.get("actions", [])):
                tag = f"{pb['name']}#{i}"
                if tag in inc["fired"]:
                    continue
                inc["fired"].append(tag)
                if spec["type"] == "block_ip" and inc["kind"] == "host":
                    continue  # un IOC sur un serveur n'a pas d'IP source a bloquer
                created.append(self._create_action(pb["name"], spec, inc))
        if created:
            self.store.save_incident(inc)
        return created

    def _isolation_target(self, inc) -> Optional[str]:
        cands = [inc["key"][5:]] if inc["kind"] == "host" else list(inc["targets"])
        for h in cands:
            if h in self.guard.inventory:
                return h
        return cands[0] if cands else None

    def _create_action(self, playbook: str, spec: Dict[str, Any], inc: Dict[str, Any]) -> Dict[str, Any]:
        params = dict(spec.get("params") or {})
        if spec["type"] == "isolate_host" and "host" not in params:
            params["host"] = self._isolation_target(inc)
        act = {"id": _new_id("ACT"), "incident_id": inc["id"], "playbook": playbook,
               "type": spec["type"], "connector": spec["connector"], "params": params,
               "status": "new", "created": time.time(), "executed": None, "result": None,
               "approved_by": None}
        allowed, reason, force_approval = self.guard.check(act, inc)
        if not allowed:
            act["status"] = "blocked_by_guard"
            act["result"] = {"ok": False, "detail": reason}
            self.store.save_action(act)
            self.store.audit("guard", "action_refused", {"action": act["id"], "reason": reason})
            return act
        if spec.get("require_approval") or force_approval:
            act["status"] = "pending_approval"
            act["result"] = {"ok": None, "detail": reason if force_approval and reason != "ok" else "en attente d'approbation"}
            self.store.save_action(act)
            self.store.audit("engine", "action_pending", {"action": act["id"], "type": act["type"]})
            return act
        return self._execute(act, inc, actor="playbook:" + playbook)

    def _execute(self, act, inc, actor: str):
        conn = self.connectors[act["connector"]]
        dry = conn.effective_dry_run()
        try:
            res = conn.run(act["type"], act["params"], inc, dry)
        except Exception as e:  # un connecteur defaillant ne doit pas arreter le moteur
            from .models import ActionResult
            res = ActionResult(False, dry, f"exception : {e}")
        act["executed"] = time.time()
        act["status"] = "failed" if not res.ok else ("dry_run" if res.dry_run else "done")
        act["result"] = {"ok": res.ok, "dry_run": res.dry_run, "detail": res.detail,
                         "commands": res.commands, "data": res.data}
        self.store.save_action(act)
        self.store.audit(actor, "action_" + act["status"], {"action": act["id"], "type": act["type"],
                                                            "detail": res.detail})
        inc.setdefault("history", []).append({"ts": act["executed"], "action": act["id"], "type": act["type"],
                                              "status": act["status"]})
        self.store.save_incident(inc)
        return act

    # ------------------------------------------------------------------------------------
    # Operations humaines
    # ------------------------------------------------------------------------------------
    def approve(self, action_id: str, actor: str) -> Dict[str, Any]:
        with self._lock:
            act = self.store.get_action(action_id)
            if not act:
                raise KeyError(action_id)
            if act["status"] != "pending_approval":
                raise ValueError(f"action dans l'etat {act['status']}, approbation impossible")
            inc = self._live(self.store.get_incident(act["incident_id"]))
            allowed, reason, _ = self.guard.check(act, inc)
            if not allowed:
                act["status"] = "blocked_by_guard"
                act["result"] = {"ok": False, "detail": reason}
                self.store.save_action(act)
                return act
            act["approved_by"] = actor
            self.store.audit(actor, "action_approved", {"action": action_id})
            return self._execute(act, inc, actor=actor)

    def reject(self, action_id: str, actor: str, comment: str = "") -> Dict[str, Any]:
        with self._lock:
            act = self.store.get_action(action_id)
            if not act:
                raise KeyError(action_id)
            if act["status"] != "pending_approval":
                raise ValueError(f"action dans l'etat {act['status']}, rejet impossible")
            act["status"] = "rejected"
            act["result"] = {"ok": False, "detail": f"rejetee par {actor} {comment}".strip()}
            self.store.save_action(act)
            self.store.audit(actor, "action_rejected", {"action": action_id, "comment": comment})
            return act

    def set_status(self, incident_id: str, status: str, actor: str, comment: str = ""):
        if status not in ("open", "closed", "false_positive", "authorized"):
            raise ValueError("statut inconnu")
        with self._lock:
            inc = self.store.get_incident(incident_id)
            if not inc:
                raise KeyError(incident_id)
            inc = self._live(inc)
            inc["status"] = status
            inc.setdefault("history", []).append({"ts": time.time(), "status": status, "by": actor,
                                                  "comment": comment})
            self.store.save_incident(inc)
            self.store.audit(actor, "incident_status", {"id": incident_id, "status": status, "comment": comment})
            return inc
