"""Reutilise les signatures de tools/artex_triage.py (source unique de verite).

Le module est charge depuis son chemin, sans duplication. Ordre de recherche :
variable ARTEX_TRIAGE_PATH, puis ../tools/artex_triage.py (depot), puis /app/tools (image Docker).
"""
import importlib.util
import os
import re
from pathlib import Path

_CANDIDATES = [
    os.environ.get("ARTEX_TRIAGE_PATH"),
    str(Path(__file__).resolve().parents[2] / "tools" / "artex_triage.py"),
    "/app/tools/artex_triage.py",
]


def _load():
    for cand in _CANDIDATES:
        if cand and os.path.isfile(cand):
            spec = importlib.util.spec_from_file_location("artex_triage", cand)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod
    raise ImportError("tools/artex_triage.py introuvable : definissez ARTEX_TRIAGE_PATH")


triage = _load()

UA_SIGNATURES = triage.UA_SIGNATURES
PAYLOAD_SIGNATURES = triage.PAYLOAD_SIGNATURES
SENSITIVE_PATHS = triage.SENSITIVE_PATHS
COMBINED = triage.COMBINED
parse_time = triage.parse_time

# Identifiants propres a ARTEX (en-tetes internes, cf. rules/suricata/artex.rules).
ARTEX_HEADERS = re.compile(r"X-ARTEX-Replay-Nonce|X-Artex-Hook|X-ARTEX-HAR-", re.I)
ARTEX_UA = re.compile(r"^ARTEX-Assessment/|^artex-update-check$", re.I)
ENGAGEMENT = re.compile(r"engagement=([A-Za-z0-9_.:-]+)")

# Etape de la chaine d'attaque associee a chaque etiquette (ordre croissant de gravite).
STAGES = ["recon", "exploitation", "credential_access", "execution"]


def stage_for(label: str, technique: str) -> str:
    low = label.lower()
    if "php2shell" in low and "session" in low:
        return "exploitation"
    if technique.startswith("T1110") or "hydra" in low or "brute" in low:
        return "credential_access"
    if technique == "T1190" or technique.startswith("T1059"):
        return "exploitation"
    return "recon"
