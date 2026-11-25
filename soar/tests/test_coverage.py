"""Couverture des familles d'attaques ARTEX (voir docs/COUVERTURE-ARTEX.md)."""
import json

import pytest

from artex_soar.detection import analyse_event
from artex_soar.engine import Engine
from artex_soar.models import Event
from artex_soar.parsers import parse_access_log, parse_auth_log, parse_firewall_log, parse_suricata
from artex_soar.store import Store

IP = "198.51.100.77"


def line(uri, status=200, method="GET", ua="Mozilla/5.0", ip=IP):
    return f'{ip} - - [25/Nov/2026:10:00:00 +0000] "{method} {uri} HTTP/1.1" {status} 120 "-" "{ua}"\n'


def labels(uri, **kw):
    ev = next(parse_access_log([line(uri, **kw)]))
    return {f.label for f in analyse_event(ev)}


@pytest.mark.parametrize("uri,expected", [
    ("/fetch?url=http://169.254.169.254/latest/meta-data/", "SSRF / acces aux metadonnees cloud"),
    ("/api/xml?data=%3C!ENTITY%20x%20SYSTEM%20%22file:///etc/passwd%22%3E", "XXE"),
    ("/login?user[$ne]=x&pass[$ne]=x", "Injection NoSQL"),
    ("/product.php?id=1%20UNION%20SELECT%20login,password%20FROM%20users", "SQLi (UNION / booleenne)"),
    ("/graphql?query={__schema{types{name}}}", "Introspection GraphQL"),
    ("/api/me?token=eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.", "JWT alg=none"),
    ("/?class.module.classLoader.resources.context.parent.pipeline.first.pattern=x", "Exploit connu (Spring4Shell / Shellshock)"),
])
def test_new_payload_signatures(uri, expected):
    assert any(expected in l for l in labels(uri))


def test_uploaded_webshell_execution_is_success():
    ev = next(parse_access_log([line("/uploads/avatar.php?cmd=id")]))
    f = [f for f in analyse_event(ev) if "televerse" in f.label]
    assert f and f[0].success and f[0].stage == "execution"


def test_http_login_bruteforce(engine):
    engine.ingest(parse_access_log([line("/login.php", 200, "POST") for _ in range(25)], target="lab"))
    inc = engine.store.list_incidents()[0]
    assert "Brute force HTTP (formulaire de connexion)" in inc["indicators"]


def test_idor_enumeration(engine):
    engine.ingest(parse_access_log([line(f"/api/user.php?id={i}") for i in range(40)], target="lab"))
    inc = engine.store.list_incidents()[0]
    assert any("IDOR" in k for k in inc["indicators"])


AUTH = """Nov 25 10:00:0{n} web01 sshd[123]: Failed password for invalid user admin from 198.51.100.77 port 4000{n} ssh2
"""


def test_ssh_bruteforce_then_success(engine):
    lines = [AUTH.format(n=i % 10) for i in range(25)]
    lines.append("Nov 25 10:01:00 web01 sshd[124]: Accepted password for root from 198.51.100.77 port 40100 ssh2\n")
    evs = list(parse_auth_log(lines))
    assert evs[0].kind == "auth" and evs[0].target == "web01" and evs[-1].kind == "auth_success"
    engine.ingest(evs)
    inc = engine.store.list_incidents()[0]
    assert inc["severity"] == "P1"
    assert "Connexion reussie apres brute force" in inc["successful"]


def test_port_scan_from_firewall_log(engine):
    lines = [f"Nov 25 10:00:00 fw kernel: [1.0] DROP IN=eth0 OUT= SRC={IP} DST=203.0.113.5 LEN=44 "
             f"PROTO=TCP SPT=5555 DPT={p} WINDOW=1024 SYN\n" for p in range(1, 60)]
    engine.ingest(parse_firewall_log(lines))
    inc = engine.store.list_incidents()[0]
    assert "Scan de ports" in inc["indicators"]


def test_lateral_movement_ids_alert(engine):
    rec = {"event_type": "alert", "timestamp": "2026-11-25T10:00:00Z", "src_ip": IP, "dest_ip": "10.0.0.5",
           "alert": {"signature": "ET POLICY Impacket wmiexec lateral movement", "signature_id": 1}}
    engine.ingest(parse_suricata([rec]))
    inc = engine.store.list_incidents()[0]
    assert inc["stage"] == "execution"


def test_outbound_oast_from_home_network_targets_own_host(cfg):
    cfg["detection"]["home_networks"] = ["10.0.0.0/8"]
    cfg["inventory"] = {"hosts": ["10.0.0.5"]}
    eng = Engine(cfg, Store(":memory:"))
    rec = {"event_type": "alert", "timestamp": "2026-11-25T10:00:00Z", "src_ip": "10.0.0.5",
           "dest_ip": "203.0.113.9", "alert": {"signature": "ARTEX OAST callback (interactsh)", "signature_id": 2}}
    eng.ingest(parse_suricata([rec]))
    inc = eng.store.list_incidents()[0]
    assert inc["key"] == "host:10.0.0.5"
    assert not [a for a in eng.store.list_actions() if a["type"] == "block_ip"], "on ne bloque pas son propre serveur"


def test_rewritemap_blocklist(cfg, tmp_path):
    from artex_soar.connectors.blocklist import BlocklistFileConnector
    c = BlocklistFileConnector("lab", {"type": "blocklist_file", "format": "rewritemap", "dry_run": False,
                                       "path": str(tmp_path / "blocked.txt")}, cfg)
    res = c.run("block_ip", {}, {"id": "INC-1", "source_ip": IP}, False)
    assert res.ok
    content = (tmp_path / "blocked.txt").read_text()
    assert f"{IP} blocked" in content.splitlines()
