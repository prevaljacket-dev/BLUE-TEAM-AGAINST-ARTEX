"""Modeles de donnees normalises."""
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

SEVERITIES = ["P3", "P2", "P1"]  # P1 = compromission probable (cf. playbook/PLAYBOOK.md)


def sev_rank(sev: Optional[str]) -> int:
    return SEVERITIES.index(sev) if sev in SEVERITIES else -1


@dataclass
class Event:
    """Evenement de securite normalise, quelle que soit la source."""
    ts: float
    kind: str                      # http | ids | host | auth
    source_ip: Optional[str] = None
    target: Optional[str] = None   # serveur / vhost de VOTRE infrastructure
    sensor: str = "unknown"
    method: str = ""
    uri: str = ""
    status: Optional[int] = None
    user_agent: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    signature: str = ""            # message IDS / raison IOC
    signature_id: Optional[int] = None
    raw: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    label: str
    weight: int
    technique: str
    stage: str
    success: bool = False          # la requete semble avoir abouti (2xx/5xx)
    artex: bool = False            # identifiant specifique ARTEX
    engagement: Optional[str] = None


@dataclass
class ActionResult:
    ok: bool
    dry_run: bool
    detail: str
    commands: List[List[str]] = field(default_factory=list)
    data: Dict[str, Any] = field(default_factory=dict)
