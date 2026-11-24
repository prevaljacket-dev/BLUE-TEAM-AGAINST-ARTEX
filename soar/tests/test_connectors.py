import os

from artex_soar.connectors.blocklist import BlocklistFileConnector
from artex_soar.connectors.firewall import IpsetConnector, NftablesConnector
from artex_soar.connectors.host import CommandConnector

INC = {"id": "INC-1", "source_ip": "198.51.100.66", "targets": ["web01"]}


def test_nftables_ipv4_and_ipv6():
    c = NftablesConnector("nft", {}, {"mode": "enforce"})
    assert c.effective_dry_run()  # dry_run implicite pour un connecteur perturbateur
    r = c.run("block_ip", {"ttl": 3600}, INC, True)
    assert r.commands == [["nft", "add", "element", "inet", "filter", "artex_soar_block",
                           "{ 198.51.100.66 timeout 3600s }"]]
    r6 = c.run("block_ip", {}, {**INC, "source_ip": "2001:db8::1"}, True)
    assert r6.commands[0][5] == "artex_soar_block6"


def test_invalid_ip_rejected():
    c = IpsetConnector("ipset", {}, {"mode": "enforce"})
    r = c.run("block_ip", {}, {**INC, "source_ip": "1.2.3.4; rm -rf /"}, True)
    assert not r.ok and not r.commands


def test_enforce_requires_both_global_and_connector():
    assert NftablesConnector("n", {"dry_run": False}, {"mode": "dry_run"}).effective_dry_run()
    assert not NftablesConnector("n", {"dry_run": False}, {"mode": "enforce"}).effective_dry_run()


def test_blocklist_file_written_and_expired_purged(tmp_path):
    soar = {"mode": "enforce", "_base_dir": str(tmp_path)}
    c = BlocklistFileConnector("b", {"dry_run": False, "path": "bl/deny.conf"}, soar)
    r = c.run("block_ip", {"ttl": 600}, INC, False)
    assert r.ok and not r.dry_run
    content = open(tmp_path / "bl" / "deny.conf").read()
    assert "deny 198.51.100.66;" in content


def test_command_connector_substitutes_without_shell():
    c = CommandConnector("iso", {"argv": ["isolate", "{host}", "--ref", "{incident_id}"]}, {"mode": "dry_run"})
    r = c.run("isolate_host", {"host": "web01"}, INC, True)
    assert r.dry_run and r.commands == [["isolate", "web01", "--ref", "INC-1"]]
