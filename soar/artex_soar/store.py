"""Persistance SQLite (incidents, actions, journal d'audit)."""
import json
import os
import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
  id TEXT PRIMARY KEY, key TEXT, status TEXT, severity TEXT, updated REAL, data TEXT);
CREATE INDEX IF NOT EXISTS ix_inc_key ON incidents(key);
CREATE TABLE IF NOT EXISTS actions (
  id TEXT PRIMARY KEY, incident_id TEXT, status TEXT, created REAL, data TEXT);
CREATE INDEX IF NOT EXISTS ix_act_inc ON actions(incident_id);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, actor TEXT, event TEXT, data TEXT);
"""


class Store:
    def __init__(self, path: str):
        if path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.executescript(SCHEMA)
        self._lock = threading.RLock()

    # -- incidents -------------------------------------------------------------------------
    def save_incident(self, inc: Dict[str, Any]):
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO incidents(id,key,status,severity,updated,data) VALUES(?,?,?,?,?,?)",
                (inc["id"], inc["key"], inc["status"], inc["severity"], inc["last_seen"],
                 json.dumps(inc, ensure_ascii=False)))
            self._db.commit()

    def get_incident(self, inc_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._db.execute("SELECT data FROM incidents WHERE id=?", (inc_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def latest_incident(self, key: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._db.execute(
                "SELECT data FROM incidents WHERE key=? ORDER BY updated DESC LIMIT 1", (key,)).fetchone()
        return json.loads(row[0]) if row else None

    def list_incidents(self, status: str = None, limit: int = 200) -> List[Dict[str, Any]]:
        q, args = "SELECT data FROM incidents", []
        if status:
            q += " WHERE status=?"
            args.append(status)
        q += " ORDER BY updated DESC LIMIT ?"
        args.append(limit)
        with self._lock:
            rows = self._db.execute(q, args).fetchall()
        return [json.loads(r[0]) for r in rows]

    # -- actions ---------------------------------------------------------------------------
    def save_action(self, act: Dict[str, Any]):
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO actions(id,incident_id,status,created,data) VALUES(?,?,?,?,?)",
                (act["id"], act["incident_id"], act["status"], act["created"],
                 json.dumps(act, ensure_ascii=False)))
            self._db.commit()

    def get_action(self, act_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._db.execute("SELECT data FROM actions WHERE id=?", (act_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def list_actions(self, status: str = None, incident_id: str = None, limit: int = 500):
        q, cond, args = "SELECT data FROM actions", [], []
        if status:
            cond.append("status=?")
            args.append(status)
        if incident_id:
            cond.append("incident_id=?")
            args.append(incident_id)
        if cond:
            q += " WHERE " + " AND ".join(cond)
        q += " ORDER BY created DESC LIMIT ?"
        args.append(limit)
        with self._lock:
            rows = self._db.execute(q, args).fetchall()
        return [json.loads(r[0]) for r in rows]

    def count_actions_since(self, action_type: str, since: float, statuses) -> int:
        n = 0
        for a in self.list_actions(limit=5000):
            if a["type"] == action_type and a["status"] in statuses and (a.get("executed") or 0) >= since:
                n += 1
        return n

    # -- audit -----------------------------------------------------------------------------
    def audit(self, actor: str, event: str, data: Dict[str, Any] = None):
        with self._lock:
            self._db.execute("INSERT INTO audit(ts,actor,event,data) VALUES(?,?,?,?)",
                             (time.time(), actor, event, json.dumps(data or {}, ensure_ascii=False)))
            self._db.commit()

    def list_audit(self, limit: int = 200):
        with self._lock:
            rows = self._db.execute(
                "SELECT ts,actor,event,data FROM audit ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [{"ts": r[0], "actor": r[1], "event": r[2], "data": json.loads(r[3])} for r in rows]
