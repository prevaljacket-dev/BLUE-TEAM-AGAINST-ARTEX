"""Garde-fous : empechent toute action dangereuse ou hors de votre perimetre."""
import ipaddress
import re
import time
from typing import Any, Dict, Optional, Tuple

HOSTNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,252}$")


def valid_ip(value: Optional[str]) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except (ValueError, TypeError):
        return False


class Guard:
    def __init__(self, cfg: Dict[str, Any], store):
        g = cfg["guard"]
        self.protected = [ipaddress.ip_network(n, strict=False) for n in g.get("protected_networks", [])]
        self.authorized = [ipaddress.ip_network(n, strict=False) for n in g.get("authorized_sources", [])]
        self.engagements = set(g.get("authorized_engagements", []))
        self.max_blocks = int(g.get("max_blocks_per_hour", 50))
        self.inventory = set(cfg.get("inventory", {}).get("hosts", []) or [])
        self.store = store

    def _in(self, ip: str, nets) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except (ValueError, TypeError):
            return False
        return any(addr in n for n in nets)

    def is_authorized(self, ip: Optional[str], engagement: Optional[str]) -> bool:
        return bool((ip and self._in(ip, self.authorized)) or (engagement and engagement in self.engagements))

    def check(self, action: Dict[str, Any], incident: Dict[str, Any]) -> Tuple[bool, str, bool]:
        """Retourne (autorise, raison, approbation_forcee)."""
        typ = action["type"]
        if typ == "block_ip":
            ip = incident.get("source_ip")
            if not valid_ip(ip):
                return False, f"adresse IP invalide ou absente : {ip!r}", False
            if self._in(ip, self.protected):
                return False, f"{ip} appartient a un reseau protege", False
            if self._in(ip, self.authorized):
                return False, f"{ip} est une source de pentest autorisee", False
            recent = self.store.count_actions_since("block_ip", time.time() - 3600, {"done", "dry_run"})
            if recent >= self.max_blocks:
                return True, f"plafond de {self.max_blocks} blocages/heure atteint : approbation requise", True
            return True, "ok", False
        if typ == "isolate_host":
            host = action.get("params", {}).get("host")
            if not host:
                return False, "aucun serveur cible connu pour cet incident", False
            if not HOSTNAME.match(host):
                return False, f"nom d'hote invalide : {host!r}", False
            if host not in self.inventory:
                return False, f"{host} n'est pas dans l'inventaire (inventory.hosts) : isolation refusee", False
            return True, "ok", True  # toujours une approbation humaine
        return True, "ok", False
