"""Ingestion : convertit les formats courants en Event normalises."""
import json
from datetime import datetime
from typing import Any, Dict, Iterable, Iterator, List, Optional

from .models import Event
from .signatures import COMBINED, parse_time


def _iso_ts(value: Any, default: float) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str) and value:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except ValueError:
            pass
        ts = parse_time(value)
        if ts is not None:
            return ts
    return default


def parse_access_line(line: str, sensor: str = "web", target: Optional[str] = None,
                      now: float = 0.0) -> Optional[Event]:
    """Ligne de journal Apache/Nginx au format combined."""
    m = COMBINED.match(line)
    if not m:
        return None
    req = (m.group("req") or "").split(" ")
    method, uri = (req[0], req[1]) if len(req) > 1 else ("", req[0])
    ts = parse_time(m.group("time"))
    return Event(ts=ts if ts is not None else now, kind="http", source_ip=m.group("ip"),
                 target=target, sensor=sensor, method=method, uri=uri,
                 status=int(m.group("status")), user_agent=m.group("ua") or "",
                 raw=line.rstrip("\n")[:2000])


def parse_access_log(lines: Iterable[str], sensor: str = "web", target: Optional[str] = None,
                     now: float = 0.0) -> Iterator[Event]:
    for line in lines:
        ev = parse_access_line(line, sensor, target, now)
        if ev:
            yield ev


def parse_suricata(records: Iterable[Any], now: float = 0.0) -> Iterator[Event]:
    """Enregistrements EVE JSON de Suricata (dict ou chaines JSON). Seuls les 'alert' sont gardes."""
    for rec in records:
        if isinstance(rec, str):
            rec = rec.strip()
            if not rec:
                continue
            try:
                rec = json.loads(rec)
            except json.JSONDecodeError:
                continue
        if not isinstance(rec, dict) or rec.get("event_type") != "alert":
            continue
        alert = rec.get("alert", {})
        http = rec.get("http", {}) or {}
        yield Event(ts=_iso_ts(rec.get("timestamp"), now), kind="ids",
                    source_ip=rec.get("src_ip"), target=http.get("hostname") or rec.get("dest_ip"),
                    sensor="suricata", method=http.get("http_method", ""), uri=http.get("url", ""),
                    status=http.get("status"), user_agent=http.get("http_user_agent", ""),
                    signature=alert.get("signature", ""), signature_id=alert.get("signature_id"),
                    raw=json.dumps(rec)[:2000])


def parse_triage_host(report: Dict[str, Any], now: float = 0.0) -> List[Event]:
    """Rapport JSON de `artex_triage.py host` -> un Event 'host' par IOC trouve."""
    host = report.get("hote", "inconnu")
    ts = _iso_ts(report.get("date"), now)
    events = []
    mapping = {
        "sessions_php_piegees": "Session PHP piegee (php2shell)",
        "webshells": "Webshell",
        "processus_artex": "Processus ARTEX sur l'hote",
        "ports_artex_en_ecoute": "Port ARTEX en ecoute",
        "fichiers_artex": "Binaire/config ARTEX",
    }
    for key, label in mapping.items():
        for item in report.get(key, []) or []:
            events.append(Event(ts=ts, kind="host", target=host, sensor="artex_triage",
                                signature=label, raw=json.dumps(item, ensure_ascii=False)[:2000]))
    return events


def parse_triage_logs(report: Dict[str, Any], now: float = 0.0) -> List[Event]:
    """Rapport JSON de `artex_triage.py logs` -> on rejoue les exemples de chaque source."""
    events = []
    for src in report.get("sources_suspectes", []) or []:
        for line in src.get("exemples", []) or []:
            ev = parse_access_line(line, sensor="artex_triage", now=now)
            if ev:
                events.append(ev)
    return events


def parse_generic(items: Iterable[Dict[str, Any]], now: float = 0.0) -> List[Event]:
    """Evenements deja normalises (JSON) envoyes par un SIEM, un WAF ou un script maison."""
    fields = set(Event.__dataclass_fields__)
    events = []
    for it in items:
        data = {k: v for k, v in it.items() if k in fields}
        data["ts"] = _iso_ts(data.get("ts"), now)
        data.setdefault("kind", "http")
        events.append(Event(**data))
    return events
