import json

from artex_soar.engine import Engine
from artex_soar.models import Event
from artex_soar.parsers import parse_access_log, parse_suricata, parse_triage_host
from artex_soar.store import Store


def test_sample_log_gives_one_p1_artex_incident(engine, sample_lines):
    res = engine.ingest(parse_access_log(sample_lines, target="web01"))
    incs = engine.store.list_incidents()
    assert len(incs) == 1, "le visiteur legitime 192.0.2.10 ne doit pas declencher d'incident"
    inc = incs[0]
    assert inc["source_ip"] == "198.51.100.66"
    assert inc["severity"] == "P1" and inc["artex_confirmed"]
    assert "Charge: inclusion de session PHP (php2shell)" in inc["successful"]
    assert res["actions"]


def test_dry_run_by_default_never_executes_blocking(engine, sample_lines, monkeypatch):
    import subprocess
    called = []
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: called.append(a))
    engine.ingest(parse_access_log(sample_lines, target="web01"))
    blocks = [a for a in engine.store.list_actions() if a["type"] == "block_ip"]
    assert blocks and all(a["status"] == "dry_run" for a in blocks)
    assert "nft" in blocks[-1]["result"]["commands"][0][0] or any(
        "nft" in c[0] for a in blocks for c in a["result"]["commands"])
    assert called == []


def test_isolation_requires_approval_and_stays_dry_run(engine, sample_lines):
    engine.ingest(parse_access_log(sample_lines, target="web01"))
    pending = engine.store.list_actions(status="pending_approval")
    assert [a["type"] for a in pending] == ["isolate_host"]
    assert pending[0]["params"]["host"] == "web01"
    act = engine.approve(pending[0]["id"], "analyste")
    assert act["status"] == "dry_run" and act["approved_by"] == "analyste"
    assert act["result"]["commands"][0][1] == "web01"


def test_reject(engine, sample_lines):
    engine.ingest(parse_access_log(sample_lines, target="web01"))
    pending = engine.store.list_actions(status="pending_approval")[0]
    assert engine.reject(pending["id"], "analyste", "pas maintenant")["status"] == "rejected"


def test_isolation_refused_outside_inventory(cfg, sample_lines):
    cfg["inventory"] = {"hosts": []}
    eng = Engine(cfg, Store(":memory:"))
    eng.ingest(parse_access_log(sample_lines, target="web01"))
    iso = [a for a in eng.store.list_actions() if a["type"] == "isolate_host"][0]
    assert iso["status"] == "blocked_by_guard"


def test_protected_network_is_never_blocked(cfg, sample_lines):
    cfg["guard"]["protected_networks"].append("198.51.100.0/24")
    eng = Engine(cfg, Store(":memory:"))
    eng.ingest(parse_access_log(sample_lines))
    blocks = [a for a in eng.store.list_actions() if a["type"] == "block_ip"]
    assert blocks and all(a["status"] == "blocked_by_guard" for a in blocks)


def test_authorized_engagement_only_notifies(cfg, sample_lines):
    cfg["guard"]["authorized_engagements"] = ["demo"]
    eng = Engine(cfg, Store(":memory:"))
    eng.ingest(parse_access_log(sample_lines, target="web01"))
    inc = eng.store.list_incidents()[0]
    assert inc["status"] == "authorized"
    assert {a["type"] for a in eng.store.list_actions()} == {"notify"}


def test_block_rate_limit_forces_approval(cfg):
    cfg["guard"]["max_blocks_per_hour"] = 1
    eng = Engine(cfg, Store(":memory:"))
    for ip in ("198.51.100.1", "198.51.100.2"):
        eng.ingest([Event(ts=1000, kind="http", source_ip=ip, uri="/", status=200,
                          user_agent="ARTEX-Assessment/1.0 (engagement=x)")])
    statuses = [a["status"] for a in eng.store.list_actions() if a["type"] == "block_ip"]
    assert "pending_approval" in statuses


def test_host_ioc_escalates_attacking_source(engine):
    engine.ingest([Event(ts=1000, kind="http", source_ip="203.0.113.9", target="web01",
                         uri="/page.php?id=1%20UNION%20ALL%20SELECT%20NULL--", status=403,
                         user_agent="sqlmap/1.9.9")])
    src = engine.store.list_incidents()[0]
    assert src["severity"] == "P3"
    report = {"hote": "web01", "date": "2026-11-24T10:05:00+00:00", "webshells": [{"chemin": "/var/www/x.php"}]}
    engine.ingest(parse_triage_host(report, now=1100))
    incs = {i["key"]: i for i in engine.store.list_incidents()}
    assert incs["host:web01"]["severity"] == "P1"
    assert incs["203.0.113.9"]["severity"] == "P1"


def test_suricata_artex_sid(engine):
    rec = {"timestamp": "2026-11-24T10:00:00.000000+0000", "event_type": "alert", "src_ip": "198.51.100.7",
           "dest_ip": "10.0.0.5", "alert": {"signature_id": 9100003, "signature": "ARTEX - En-tete interne X-ARTEX-Replay-Nonce"}}
    engine.ingest(parse_suricata([json.dumps(rec)]))
    inc = engine.store.list_incidents()[0]
    assert inc["artex_confirmed"] and inc["source_ip"] == "198.51.100.7"


def test_closed_incident_reopens_new_one(engine):
    ev = dict(kind="http", source_ip="198.51.100.8", uri="/", status=200, user_agent="ARTEX-Assessment/1.0")
    engine.ingest([Event(ts=1000, **ev)])
    first = engine.store.list_incidents()[0]
    engine.set_status(first["id"], "closed", "analyste")
    engine.ingest([Event(ts=1010, **ev)])
    ids = {i["id"] for i in engine.store.list_incidents()}
    assert len(ids) == 2


def test_playbook_actions_fire_once(engine, sample_lines):
    engine.ingest(parse_access_log(sample_lines[:200], target="web01"))
    n = len(engine.store.list_actions())
    engine.ingest(parse_access_log(sample_lines[:200], target="web01"))
    assert len(engine.store.list_actions()) == n


def test_host_incident_does_not_try_to_block_an_ip(engine):
    report = {"hote": "web01", "date": "2026-11-24T10:05:00+00:00", "webshells": [{"chemin": "/var/www/x.php"}]}
    engine.ingest(parse_triage_host(report, now=1100))
    types = {a["type"] for a in engine.store.list_actions()}
    assert "block_ip" not in types and "collect_evidence" in types
