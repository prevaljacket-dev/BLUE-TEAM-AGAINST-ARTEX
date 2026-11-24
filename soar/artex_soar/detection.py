"""Detection : evenement -> constats (Finding), puis suivi comportemental par source."""
import re
from collections import OrderedDict, deque
from typing import Dict, List, Optional
from urllib.parse import unquote_plus

from .models import Event, Finding
from .signatures import (ARTEX_HEADERS, ARTEX_UA, ENGAGEMENT, PAYLOAD_SIGNATURES, SENSITIVE_PATHS,
                         UA_SIGNATURES, stage_for)

# Plages de SID de rules/suricata/artex.rules
SID_ARTEX_IDENTIFIERS = range(9100001, 9100020)
SID_PHP2SHELL = range(9100040, 9100043)


def _success(status: Optional[int]) -> bool:
    return status is not None and (200 <= status < 300 or 500 <= status < 600)


def analyse_event(ev: Event) -> List[Finding]:
    """Constats ponctuels pour un evenement (reutilise les signatures d'artex_triage)."""
    out: List[Finding] = []
    engagement = None
    if ev.user_agent:
        m = ENGAGEMENT.search(ev.user_agent)
        engagement = m.group(1) if m else None

    if ev.kind in ("http", "ids"):
        ua = ev.user_agent or ""
        for rx, label, weight, tech in UA_SIGNATURES:
            if rx.search(ua):
                out.append(Finding("UA: " + label, weight, tech, stage_for(label, tech),
                                   artex=bool(ARTEX_UA.search(ua)), engagement=engagement))
        uri = ev.uri or ""
        decoded = unquote_plus(unquote_plus(uri))
        for rx, label, weight, tech in PAYLOAD_SIGNATURES:
            if rx.search(decoded) or rx.search(uri):
                out.append(Finding("Charge: " + label, weight, tech, stage_for(label, tech),
                                   success=_success(ev.status)))
        for name in ev.headers or {}:
            if ARTEX_HEADERS.search(name):
                out.append(Finding(f"En-tete ARTEX: {name}", 100, "T1595", "recon", artex=True))

    if ev.kind == "ids" and ev.signature:
        sid = ev.signature_id or 0
        msg = ev.signature
        if sid in SID_PHP2SHELL or "php2shell" in msg.lower():
            out.append(Finding("IDS: " + msg, 80, "T1190", "exploitation", success=_success(ev.status)))
        elif sid in SID_ARTEX_IDENTIFIERS:
            out.append(Finding("IDS: " + msg, 100, "T1595", "recon", artex=True))
        elif "artex" in msg.lower():
            low = msg.lower()
            stage = ("credential_access" if "brute" in low or "hydra" in low
                     else "exploitation" if re.search(r"sqlmap|lfi|traversee|oast|injection", low)
                     else "recon")
            out.append(Finding("IDS: " + msg, 40, "T1595", stage))
        else:
            out.append(Finding("IDS: " + msg, 20, "T1595", "recon"))

    if ev.kind == "host":
        out.append(Finding("IOC hote: " + (ev.signature or "inconnu"), 100, "T1059", "execution",
                           success=True, artex="ARTEX" in (ev.signature or "")))

    if ev.kind == "auth":
        out.append(Finding("Echec d'authentification", 2, "T1110", "credential_access"))
    return out


class SourceTracker:
    """Statistiques glissantes par source pour les signaux comportementaux
    (rafale, enumeration, rotation d'UA, brute force) qui resistent au changement d'UA."""

    def __init__(self):
        self.times: deque = deque()
        self.paths = set()
        self.uas = set()
        self.count = 0
        self.errors = 0
        self.sensitive = 0
        self.auth_failures = 0
        self.max_rate = 0
        self.last = 0.0

    def update(self, ev: Event, window: float = 10.0):
        self.count += 1
        self.last = ev.ts
        self.times.append(ev.ts)
        while self.times and ev.ts - self.times[0] > window:
            self.times.popleft()
        self.max_rate = max(self.max_rate, len(self.times))
        if ev.uri and len(self.paths) < 5000:
            self.paths.add(ev.uri.split("?")[0])
        if ev.user_agent and len(self.uas) < 50:
            self.uas.add(ev.user_agent)
        if ev.status is not None and 400 <= ev.status < 500:
            self.errors += 1
        if ev.uri and SENSITIVE_PATHS.search(ev.uri):
            self.sensitive += 1
        if ev.kind == "auth":
            self.auth_failures += 1

    def behaviour(self, burst_threshold: int) -> List[Finding]:
        out = []
        if self.max_rate >= burst_threshold:
            out.append(Finding("Rafale de requetes", 30, "T1595", "recon"))
        if len(self.paths) >= 200 and self.count and self.errors / self.count > 0.6:
            out.append(Finding("Enumeration de chemins (forte proportion de 404/403)", 30,
                               "T1595.003", "recon"))
        if self.sensitive >= 10:
            out.append(Finding("Chemins sensibles sondes", 15, "T1595", "recon"))
        if len(self.uas) >= 5:
            out.append(Finding("Rotation de User-Agent", 15, "T1036", "recon"))
        if self.auth_failures >= 20:
            out.append(Finding("Brute force (echecs d'authentification repetes)", 60, "T1110",
                               "credential_access"))
        return out


class TrackerPool:
    """Pool LRU borne de SourceTracker."""

    def __init__(self, max_size: int = 100000):
        self.max_size = max_size
        self._items: "OrderedDict[str, SourceTracker]" = OrderedDict()

    def get(self, key: str) -> SourceTracker:
        tr = self._items.get(key)
        if tr is None:
            tr = SourceTracker()
            self._items[key] = tr
            if len(self._items) > self.max_size:
                self._items.popitem(last=False)
        else:
            self._items.move_to_end(key)
        return tr

    def reset(self, key: str):
        self._items.pop(key, None)

    def __len__(self):
        return len(self._items)
