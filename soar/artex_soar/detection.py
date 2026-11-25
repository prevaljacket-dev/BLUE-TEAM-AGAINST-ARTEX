"""Detection : evenement -> constats (Finding), puis suivi comportemental par source."""
import re
from collections import OrderedDict, deque
from typing import Dict, List, Optional
from urllib.parse import unquote_plus

from .models import Event, Finding

from .signatures import (ARTEX_HEADERS, ARTEX_UA, ENGAGEMENT, EXTRA_PAYLOAD_SIGNATURES, LATERAL_IDS, LOGIN_PATH,
                         PAYLOAD_SIGNATURES, SENSITIVE_PATHS, UA_SIGNATURES, UPLOAD_EXEC, stage_for)

ALL_PAYLOAD_SIGNATURES = list(PAYLOAD_SIGNATURES) + EXTRA_PAYLOAD_SIGNATURES
ID_SEGMENT = re.compile(r"/(\d{1,12}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?=/|$)", re.I)
ID_PARAM = re.compile(r"[?&](id|user_?id|uid|account|order|invoice|doc|file_?id)=(\d{1,12})\b", re.I)

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
        for rx, label, weight, tech in ALL_PAYLOAD_SIGNATURES:
            if rx.search(decoded) or rx.search(uri) or (label.startswith("Exploit connu") and rx.search(ua)):
                out.append(Finding("Charge: " + label, weight, tech, stage_for(label, tech),
                                   success=_success(ev.status)))
        if UPLOAD_EXEC.search(uri) and ev.status is not None and 200 <= ev.status < 300:
            out.append(Finding("Execution d'un fichier televerse (webshell probable)", 100, "T1505.003",
                               "execution", success=True))
        for name in ev.headers or {}:
            if ARTEX_HEADERS.search(name):
                out.append(Finding(f"En-tete ARTEX: {name}", 100, "T1595", "recon", artex=True))

    if ev.kind == "ids" and ev.signature:
        sid = ev.signature_id or 0
        msg = ev.signature
        if LATERAL_IDS.search(msg):
            out.append(Finding("IDS mouvement lateral: " + msg, 80, "T1021", "execution", success=True))
        elif sid in SID_PHP2SHELL or "php2shell" in msg.lower():
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
    if ev.kind == "auth_success":
        out.append(Finding("Authentification reussie", 0, "T1078", "recon"))
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
        self.login_posts = 0
        self.ports = set()
        self.id_values = {}
        self.auth_success_after_failures = False

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
        if ev.kind == "auth_success" and self.auth_failures >= 5:
            self.auth_success_after_failures = True
        if ev.kind == "conn" and ev.signature.isdigit() and len(self.ports) < 70000:
            self.ports.add(int(ev.signature))
        if ev.kind == "http" and ev.method.upper() == "POST" and ev.uri and LOGIN_PATH.search(ev.uri.split("?")[0]):
            self.login_posts += 1
        if ev.kind == "http" and ev.uri:
            path, _, query = ev.uri.partition("?")
            template = ID_SEGMENT.sub("/{id}", path)
            vals = [m.group(1) for m in ID_SEGMENT.finditer(path)]
            for m in ID_PARAM.finditer("?" + query):
                template += "?" + m.group(1).lower() + "={id}"
                vals.append(m.group(2))
            if vals and len(self.id_values) < 200:
                self.id_values.setdefault(template, set())
                if len(self.id_values[template]) < 1000:
                    self.id_values[template].update(vals)

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
        if self.auth_success_after_failures:
            out.append(Finding("Connexion reussie apres brute force", 100, "T1110", "execution", success=True))
        if self.login_posts >= 20:
            out.append(Finding("Brute force HTTP (formulaire de connexion)", 60, "T1110.001", "credential_access"))
        if len(self.ports) >= 20:
            out.append(Finding("Scan de ports", 40, "T1046", "recon"))
        if any(len(v) >= 30 for v in self.id_values.values()):
            out.append(Finding("Enumeration d'identifiants d'objets (IDOR / BOLA)", 40, "T1190", "exploitation"))
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
