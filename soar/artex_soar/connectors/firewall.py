"""Blocage d'IP sur VOTRE pare-feu (nftables, ipset/iptables), avec expiration native."""
import ipaddress

from ..guard import valid_ip
from ..models import ActionResult
from .base import Connector


def _ttl(params, cfg) -> int:
    return max(60, int(params.get("ttl", cfg.get("default_ttl", 86400))))


class NftablesConnector(Connector):
    """Ajoute l'IP a un set nftables avec timeout. Prerequis (une fois) :

        nft add table inet filter
        nft add set inet filter artex_soar_block  '{ type ipv4_addr; flags timeout; }'
        nft add set inet filter artex_soar_block6 '{ type ipv6_addr; flags timeout; }'
        nft add rule inet filter input ip  saddr @artex_soar_block  drop
        nft add rule inet filter input ip6 saddr @artex_soar_block6 drop
    """
    disruptive = True
    supports = ("block_ip",)

    def run(self, action_type, params, incident, dry_run):
        ip = incident.get("source_ip")
        if not valid_ip(ip):
            return ActionResult(False, dry_run, f"IP invalide : {ip!r}")
        v6 = ipaddress.ip_address(ip).version == 6
        family = self.cfg.get("family", "inet")
        table = self.cfg.get("table", "filter")
        set_name = self.cfg.get("set6" if v6 else "set", "artex_soar_block6" if v6 else "artex_soar_block")
        nft = self.cfg.get("binary", "nft")
        cmd = [nft, "add", "element", family, table, set_name, "{ %s timeout %ds }" % (ip, _ttl(params, self.cfg))]
        res = self.exec_commands([cmd], dry_run)
        res.data["ip"] = ip
        return res


class IpsetConnector(Connector):
    """Ajoute l'IP a un ipset avec timeout (a referencer dans une regle iptables). Prerequis :

        ipset create artex_soar_block hash:ip timeout 0
        iptables -I INPUT -m set --match-set artex_soar_block src -j DROP
    """
    disruptive = True
    supports = ("block_ip",)

    def run(self, action_type, params, incident, dry_run):
        ip = incident.get("source_ip")
        if not valid_ip(ip):
            return ActionResult(False, dry_run, f"IP invalide : {ip!r}")
        v6 = ipaddress.ip_address(ip).version == 6
        set_name = self.cfg.get("set6" if v6 else "set", "artex_soar_block6" if v6 else "artex_soar_block")
        cmd = [self.cfg.get("binary", "ipset"), "add", set_name, ip, "timeout", str(_ttl(params, self.cfg)), "-exist"]
        res = self.exec_commands([cmd], dry_run)
        res.data["ip"] = ip
        return res
