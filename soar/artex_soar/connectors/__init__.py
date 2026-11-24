"""Registre des connecteurs. Ajouter un connecteur : sous-classer Connector et l'enregistrer ici."""
from typing import Any, Dict

from .base import Connector
from .blocklist import BlocklistFileConnector
from .evidence import EvidenceConnector
from .firewall import IpsetConnector, NftablesConnector
from .host import CommandConnector
from .notify import EmailConnector, LogConnector, TicketFileConnector, WebhookConnector

REGISTRY = {
    "log": LogConnector,
    "webhook": WebhookConnector,
    "email": EmailConnector,
    "ticket_file": TicketFileConnector,
    "evidence": EvidenceConnector,
    "nftables": NftablesConnector,
    "ipset": IpsetConnector,
    "blocklist_file": BlocklistFileConnector,
    "command": CommandConnector,
}


def build_connectors(cfg: Dict[str, Any]) -> Dict[str, Connector]:
    out = {}
    for name, ccfg in (cfg.get("connectors") or {}).items():
        typ = ccfg.get("type", name)
        if typ not in REGISTRY:
            raise ValueError(f"connecteur {name}: type inconnu {typ!r} (connus : {', '.join(REGISTRY)})")
        out[name] = REGISTRY[typ](name, ccfg, cfg)
    return out
