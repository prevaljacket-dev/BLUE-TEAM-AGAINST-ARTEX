#!/usr/bin/env python3
"""
artex_triage.py - Outil de triage blue team face a ARTEX (plateforme de pentest autonome).

Strictement defensif et en lecture seule : il lit des journaux et des fichiers,
ne modifie rien, ne contacte aucun hote.

Sous-commandes :
  logs  Analyse des journaux d'acces Apache/Nginx (format "combined") et score par IP source.
  host  Chasse aux IOC sur un serveur (sessions PHP piegees, webshells, instance ARTEX locale).

Exemples :
  python3 artex_triage.py logs /var/log/nginx/access.log* --json rapport.json
  sudo python3 artex_triage.py host --webroot /var/www --json host.json

Python 3.8+, bibliotheque standard uniquement.
"""
import argparse
import gzip
import hashlib
import json
import os
import re
import socket
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from urllib.parse import unquote_plus

# --------------------------------------------------------------------------------------
# Signatures
# --------------------------------------------------------------------------------------

UA_SIGNATURES = [
    # (motif, etiquette, poids, technique ATT&CK)
    (re.compile(r"^ARTEX-Assessment/", re.I), "ARTEX-Assessment (identifiant ARTEX)", 100, "T1595"),
    (re.compile(r"sqlmap/", re.I), "sqlmap", 60, "T1190"),
    (re.compile(r"Fuzz Faster U Fool", re.I), "ffuf", 50, "T1595.003"),
    (re.compile(r"Nmap Scripting Engine", re.I), "nmap NSE", 40, "T1595.002"),
    (re.compile(r"\(Hydra\)", re.I), "hydra", 60, "T1110"),
    (re.compile(r"HeadlessChrome", re.I), "Chromium headless (Playwright)", 20, "T1595"),
    (re.compile(r"nuclei", re.I), "nuclei", 50, "T1595.002"),
    (re.compile(r"dalfox", re.I), "dalfox", 50, "T1190"),
    (re.compile(r"katana|httpx|projectdiscovery", re.I), "outil ProjectDiscovery", 40, "T1595"),
    (re.compile(r"bbot", re.I), "bbot", 40, "T1595"),
    (re.compile(r"python-requests|python-urllib|aiohttp|Go-http-client|curl/|Wget/", re.I),
     "client HTTP script", 5, "T1595"),
]

PAYLOAD_SIGNATURES = [
    (re.compile(r"sess_[a-z0-9,-]{6,}", re.I), "inclusion de session PHP (php2shell)", 80, "T1190"),
    (re.compile(r"PHP_SESSION_UPLOAD_PROGRESS", re.I), "PHP_SESSION_UPLOAD_PROGRESS (php2shell)", 60, "T1190"),
    (re.compile(r"(\.\./){3,}|/etc/passwd|php://(filter|input)|data://text/plain|expect://", re.I),
     "LFI / traversee", 30, "T1190"),
    (re.compile(r"union(\s|\+)+all(\s|\+)+select|sleep\(\d+\)|waitfor\s+delay|extractvalue\(|updatexml\(|'\s*or\s*'?1'?\s*=\s*'?1", re.I),
     "SQLi", 25, "T1190"),
    (re.compile(r"<script|onerror\s*=|onload\s*=|javascript:alert|<svg", re.I), "XSS", 20, "T1190"),
    (re.compile(r"\.oast\.(pro|live|site|online|fun|me)|interact\.sh", re.I), "callback OAST (nuclei)", 50, "T1190"),
    (re.compile(r"\$\{jndi:|\{\{\d+\*\d+\}\}|\$\{\d+\*\d+\}", re.I), "injection template/JNDI", 30, "T1190"),
    (re.compile(r";\s*(id|whoami|uname)\b|\|\s*(id|whoami)\b|`id`|\$\(id\)", re.I), "injection de commande", 40, "T1059"),
]

SENSITIVE_PATHS = re.compile(
    r"/(\.git/|\.env|\.svn/|\.DS_Store|wp-config|phpinfo|server-status|actuator|swagger|openapi|"
    r"api-docs|graphql|\.well-known/security\.txt|backup|\.bak$|\.sql$|config\.(php|json|yml)|"
    r"admin|console|debug|v1/|v2/)",
    re.I,
)

COMBINED = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<req>[^"]*)" (?P<status>\d{3}) (?P<size>\S+)'
    r'(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?'
)

# --------------------------------------------------------------------------------------
# Analyse des journaux
# --------------------------------------------------------------------------------------


def open_any(path):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", errors="replace")
    return open(path, "r", errors="replace")


def parse_time(s):
    for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%d/%b/%Y:%H:%M:%S"):
        try:
            return datetime.strptime(s, fmt).timestamp()
        except ValueError:
            continue
    return None


class SourceStats:
    def __init__(self):
        self.count = 0
        self.first = None
        self.last = None
        self.statuses = defaultdict(int)
        self.paths = set()
        self.uas = set()
        self.hits = defaultdict(int)      # etiquette -> nombre
        self.techniques = set()
        self.score = 0
        self.samples = []
        self.times = []
        self.sensitive = 0

    def add_hit(self, label, weight, technique, line):
        if self.hits[label] == 0:
            self.score += weight
        self.hits[label] += 1
        self.techniques.add(technique)
        if len(self.samples) < 15:
            self.samples.append(line.strip()[:400])


def max_rate(times, window=10.0):
    """Nombre maximal de requetes dans une fenetre glissante de `window` secondes."""
    times = sorted(t for t in times if t is not None)
    best, j = 0, 0
    for i, t in enumerate(times):
        while t - times[j] > window:
            j += 1
        best = max(best, i - j + 1)
    return best


def analyse_logs(paths, burst_threshold=50):
    sources = defaultdict(SourceStats)
    unparsed = 0
    for path in paths:
        try:
            fh = open_any(path)
        except OSError as e:
            print(f"[!] lecture impossible {path}: {e}", file=sys.stderr)
            continue
        with fh:
            for line in fh:
                m = COMBINED.match(line)
                if not m:
                    unparsed += 1
                    continue
                ip = m.group("ip")
                st = sources[ip]
                st.count += 1
                ts = parse_time(m.group("time"))
                st.times.append(ts)
                if ts is not None:
                    st.first = ts if st.first is None else min(st.first, ts)
                    st.last = ts if st.last is None else max(st.last, ts)
                st.statuses[m.group("status")] += 1
                req = m.group("req") or ""
                parts = req.split(" ")
                uri = parts[1] if len(parts) > 1 else req
                st.paths.add(uri.split("?")[0])
                ua = m.group("ua") or ""
                st.uas.add(ua)
                decoded = unquote_plus(unquote_plus(uri))
                for rx, label, weight, tech in UA_SIGNATURES:
                    if rx.search(ua):
                        st.add_hit("UA: " + label, weight, tech, line)
                for rx, label, weight, tech in PAYLOAD_SIGNATURES:
                    if rx.search(decoded) or rx.search(uri):
                        st.add_hit("Charge: " + label, weight, tech, line)
                if SENSITIVE_PATHS.search(uri):
                    st.sensitive += 1

    results = []
    for ip, st in sources.items():
        rate = max_rate(st.times)
        errors = sum(v for k, v in st.statuses.items() if k.startswith("4"))
        err_ratio = errors / st.count if st.count else 0
        if rate >= burst_threshold:
            st.add_hit(f"Rafale: {rate} req/10s", 30, "T1595", "")
        if len(st.paths) >= 200 and err_ratio > 0.6:
            st.add_hit("Enumeration de chemins (forte proportion de 404/403)", 30, "T1595.003", "")
        if st.sensitive >= 10:
            st.add_hit(f"Chemins sensibles sondes: {st.sensitive}", 15, "T1595", "")
        if len(st.uas) >= 5:
            st.add_hit(f"Rotation de User-Agent: {len(st.uas)} UA distincts", 15, "T1036", "")
        if st.score == 0:
            continue
        level = "CRITIQUE" if st.score >= 100 else "ELEVE" if st.score >= 60 else "MOYEN" if st.score >= 30 else "FAIBLE"
        results.append({
            "ip": ip,
            "score": st.score,
            "niveau": level,
            "requetes": st.count,
            "debut": iso(st.first),
            "fin": iso(st.last),
            "pic_req_10s": rate,
            "ratio_4xx": round(err_ratio, 2),
            "chemins_distincts": len(st.paths),
            "indicateurs": dict(st.hits),
            "techniques_attack": sorted(st.techniques),
            "user_agents": sorted(st.uas)[:10],
            "exemples": st.samples,
        })
    results.sort(key=lambda r: r["score"], reverse=True)
    return {"sources_suspectes": results, "lignes_non_parsees": unparsed}


def iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).isoformat() if ts else None


# --------------------------------------------------------------------------------------
# Chasse sur l'hote
# --------------------------------------------------------------------------------------

SESSION_DIRS = ["/var/lib/php/sessions", "/var/lib/php5", "/var/lib/php/session", "/tmp", "/var/tmp"]
PHP_CODE = re.compile(rb"<\?(php|=)", re.I)
WEBSHELL = re.compile(
    rb"\b(system|passthru|shell_exec|exec|popen|proc_open|assert)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)"
    rb"|\beval\s*\(\s*(base64_decode|gzinflate|str_rot13)?\s*\(?\s*\$_(GET|POST|REQUEST|COOKIE)",
    re.I,
)
ARTEX_STRINGS = [b"ARTEX-Assessment/1.0", b"artex-update-check", b"X-ARTEX-Replay-Nonce",
                 b"ARTEX_NOISE_PROFILE", b"github.com/Autumn-27/artex"]
ARTEX_PORTS = {8787: "UI/API ARTEX", 8788: "proxy MITM ARTEX"}


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def file_info(path):
    st = os.stat(path)
    return {"chemin": path, "taille": st.st_size, "mtime": iso(st.st_mtime),
            "proprietaire_uid": st.st_uid, "sha256": sha256(path)}


def hunt_sessions(dirs):
    findings = []
    for d in dirs:
        if not os.path.isdir(d):
            continue
        try:
            names = os.listdir(d)
        except OSError:
            continue
        for n in names:
            if not n.startswith("sess_"):
                continue
            p = os.path.join(d, n)
            try:
                if not os.path.isfile(p) or os.path.getsize(p) > 2 * 1024 * 1024:
                    continue
                with open(p, "rb") as f:
                    data = f.read()
            except OSError:
                continue
            if PHP_CODE.search(data):
                info = file_info(p)
                info["raison"] = "session PHP contenant du code PHP (php2shell)"
                info["extrait"] = data[:300].decode("latin-1")
                findings.append(info)
    return findings


def hunt_webroot(roots, days):
    findings = []
    limit = time.time() - days * 86400
    for root in roots:
        for dirpath, _dirs, files in os.walk(root):
            for n in files:
                if not n.lower().endswith((".php", ".phtml", ".php5", ".php7", ".phar", ".inc")):
                    continue
                p = os.path.join(dirpath, n)
                try:
                    st = os.stat(p)
                    if st.st_size > 512 * 1024:
                        continue
                    with open(p, "rb") as f:
                        data = f.read()
                except OSError:
                    continue
                recent = st.st_mtime >= limit
                if WEBSHELL.search(data):
                    info = file_info(p)
                    info["raison"] = "motif de webshell" + (" (modifie recemment)" if recent else "")
                    findings.append(info)
    return findings


def listening_ports():
    found = []
    for proto in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(proto) as f:
                next(f)
                for line in f:
                    cols = line.split()
                    local, state = cols[1], cols[3]
                    if state != "0A":  # LISTEN
                        continue
                    port = int(local.split(":")[1], 16)
                    if port in ARTEX_PORTS:
                        found.append({"port": port, "role_probable": ARTEX_PORTS[port], "source": proto})
        except (OSError, StopIteration):
            continue
    return found


def artex_processes():
    found = []
    if not os.path.isdir("/proc"):
        return found
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                cmd = f.read().replace(b"\0", b" ").decode("latin-1").strip()
        except OSError:
            continue
        low = cmd.lower()
        if re.search(r"(^|/)artex(\s|$)", low) or "baarai/artex" in low or "artex_noise_profile" in low:
            exe = None
            try:
                exe = os.readlink(f"/proc/{pid}/exe")
            except OSError:
                pass
            found.append({"pid": int(pid), "cmdline": cmd[:300], "exe": exe})
    return found


def iter_files(root):
    if os.path.isfile(root):
        yield root
        return
    for dirpath, _d, files in os.walk(root):
        for n in files:
            yield os.path.join(dirpath, n)


def hunt_artex_files(paths):
    findings = []
    for root in paths:
        for p in iter_files(root):
            try:
                if not os.path.isfile(p) or os.path.getsize(p) > 200 * 1024 * 1024:
                    continue
                with open(p, "rb") as f:
                    data = f.read()
            except OSError:
                continue
            hits = [s.decode() for s in ARTEX_STRINGS if s in data]
            if len(hits) >= 2:
                info = file_info(p)
                info["raison"] = "chaines ARTEX: " + ", ".join(hits)
                findings.append(info)
    return findings


def analyse_host(args):
    report = {
        "hote": socket.gethostname(),
        "date": datetime.now(timezone.utc).isoformat(),
        "sessions_php_piegees": hunt_sessions(args.session_dir or SESSION_DIRS),
        "webshells": hunt_webroot(args.webroot, args.days) if args.webroot else [],
        "ports_artex_en_ecoute": listening_ports(),
        "processus_artex": artex_processes(),
        "fichiers_artex": hunt_artex_files(args.artex_path) if args.artex_path else [],
    }
    return report


# --------------------------------------------------------------------------------------
# Sortie
# --------------------------------------------------------------------------------------


def print_logs_report(rep):
    srcs = rep["sources_suspectes"]
    print(f"== Sources suspectes : {len(srcs)} (lignes non parsees : {rep['lignes_non_parsees']}) ==")
    for r in srcs:
        print(f"\n[{r['niveau']}] {r['ip']}  score={r['score']}  requetes={r['requetes']}  "
              f"pic={r['pic_req_10s']}/10s  4xx={r['ratio_4xx']}")
        print(f"  periode : {r['debut']} -> {r['fin']}")
        print(f"  ATT&CK  : {', '.join(r['techniques_attack'])}")
        for k, v in sorted(r["indicateurs"].items(), key=lambda kv: -kv[1]):
            print(f"   - {k} ({v})")
    if srcs:
        print("\nBloquer en priorite les sources CRITIQUE/ELEVE puis suivre playbook/PLAYBOOK.md.")


def print_host_report(rep):
    print(f"== Chasse IOC sur {rep['hote']} ({rep['date']}) ==")
    for key, title in [("sessions_php_piegees", "Sessions PHP piegees"), ("webshells", "Webshells"),
                       ("ports_artex_en_ecoute", "Ports ARTEX en ecoute"),
                       ("processus_artex", "Processus ARTEX"), ("fichiers_artex", "Fichiers ARTEX")]:
        items = rep[key]
        print(f"\n{title} : {len(items)}")
        for it in items:
            print("  - " + json.dumps(it, ensure_ascii=False)[:500])


def main(argv=None):
    ap = argparse.ArgumentParser(description="Triage blue team face a ARTEX (lecture seule).")
    sub = ap.add_subparsers(dest="cmd", required=True)

    lp = sub.add_parser("logs", help="analyser des journaux d'acces web (combined)")
    lp.add_argument("files", nargs="+")
    lp.add_argument("--burst", type=int, default=50, help="seuil de rafale en requetes / 10 s (defaut 50)")
    lp.add_argument("--min-score", type=int, default=0)
    lp.add_argument("--json", help="ecrire le rapport JSON dans ce fichier")

    hp = sub.add_parser("host", help="chasser les IOC sur l'hote local")
    hp.add_argument("--webroot", action="append", help="racine web a analyser (repetable)")
    hp.add_argument("--session-dir", action="append", help="repertoire de sessions PHP (repetable)")
    hp.add_argument("--artex-path", action="append", help="chemin a scanner pour un binaire/config ARTEX")
    hp.add_argument("--days", type=int, default=14, help="fenetre 'modifie recemment' (jours)")
    hp.add_argument("--json", help="ecrire le rapport JSON dans ce fichier")

    args = ap.parse_args(argv)
    if args.cmd == "logs":
        rep = analyse_logs(args.files, args.burst)
        rep["sources_suspectes"] = [r for r in rep["sources_suspectes"] if r["score"] >= args.min_score]
        print_logs_report(rep)
        crit = any(r["niveau"] in ("CRITIQUE", "ELEVE") for r in rep["sources_suspectes"])
    else:
        rep = analyse_host(args)
        print_host_report(rep)
        crit = bool(rep["sessions_php_piegees"] or rep["webshells"] or rep["processus_artex"])
    if args.json:
        with open(args.json, "w") as f:
            json.dump(rep, f, indent=2, ensure_ascii=False)
        print(f"\nRapport JSON : {args.json}")
    return 2 if crit else 0


if __name__ == "__main__":
    sys.exit(main())
