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


# --------------------------------------------------------------------------------------
# Signatures complementaires propres au SOAR (classes d'attaque des competences ARTEX
# api-security / nuclei qui ne sont pas couvertes par artex_triage.py).
# (motif, etiquette, poids, technique ATT&CK)
# --------------------------------------------------------------------------------------
EXTRA_PAYLOAD_SIGNATURES = [
  (re.compile(r"union(\s|\+|/\*.*?\*/)+(distinct(\s|\+)+)?select\b|\border(\s|\+)+by(\s|\+)+\d+(\s|\+)*(--|#)|information_schema|\b(and|or)(\s|\+)+\d+(\s|\+)*=(\s|\+)*\d+(\s|\+)*(--|#)", re.I), "SQLi (UNION / booleenne)", 30, "T1190"),
    (re.compile(r"169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|"
                r"(url|uri|dest|redirect|next|target|callback|webhook|feed|image|src|path)=(https?|file|gopher|dict|ftp)(://|%3a%2f%2f)",
                re.I), "SSRF / acces aux metadonnees cloud", 40, "T1190"),
    (re.compile(r"<!ENTITY|<!DOCTYPE[^>]*SYSTEM|%3C!ENTITY", re.I), "XXE", 40, "T1190"),
    (re.compile(r"\[\$(ne|gt|lt|regex|where|exists)\]|\{\s*\"?\$(ne|gt|regex|where)\"?\s*:", re.I),
     "Injection NoSQL", 30, "T1190"),
    (re.compile(r"__schema|IntrospectionQuery|__type\s*\(", re.I), "Introspection GraphQL", 15, "T1595"),
    (re.compile(r"eyJhbGciOiJub25l|eyJ0eXAiOiJKV1QiLCJhbGciOiJub25l", re.I), "JWT alg=none", 40, "T1190"),
    (re.compile(r"class\.module\.classLoader|\(\)\s*\{\s*:\s*;\s*\}\s*;", re.I),
     "Exploit connu (Spring4Shell / Shellshock)", 50, "T1190"),
    (re.compile(r"%0d%0a(set-cookie|location|content-)|\r\n(set-cookie|location):", re.I),
     "Injection CRLF / separation de reponse", 20, "T1190"),
]

# Fichier televerse puis execute (webshell depose via un formulaire d'upload).
UPLOAD_EXEC = re.compile(r"/(uploads?|files|media|images?|tmp|cache)/[^?#]*\.(php\d?|phtml|phar|jsp|aspx?|cgi)(\?|$)", re.I)
# Formulaires d'authentification (brute force HTTP : hydra http-post-form, bourrage d'identifiants).
LOGIN_PATH = re.compile(r"/(login|signin|sign-in|logon|auth|authenticate|session|wp-login\.php|xmlrpc\.php|"
                        r"user/login|account/login|admin/login|api/(v\d+/)?(auth|login|token))\b", re.I)
# Mots-cles d'alertes IDS de mouvement lateral (impacket, SMB, WMI, Kerberos, NFS/RPC).
LATERAL_IDS = re.compile(r"impacket|psexec|smbexec|wmiexec|dcom|secretsdump|kerberoast|as-rep|ntlm relay|"
                         r"lateral|pass.the.hash|smb.*(exec|admin\$|ipc\$)|rpcbind|nfs.*(mount|export)", re.I)
# Alertes signifiant que l'un de VOS serveurs a lui-meme contacte l'exterieur (callback OAST, mise a jour ARTEX).
OUTBOUND_IOC = re.compile(r"oast|interact\.sh|interactsh|artex-update-check|mise a jour d'une instance artex|callback", re.I)
