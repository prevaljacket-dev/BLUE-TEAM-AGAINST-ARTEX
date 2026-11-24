#!/usr/bin/env python3
"""Controles hors ligne du contenu Sentinel (pas besoin d'Azure).

1. Structure des regles YAML (champs, GUID uniques, tactiques, techniques, colonnes d'entites).
2. Syntaxe KQL de base : parentheses/crochets equilibres, chaines fermees.
3. Toutes les expressions regulieres compilent.
4. Simulation sur samples/access_demo.log : l'attaquant 198.51.100.66 declenche les regles web
   attendues, la source legitime 192.0.2.10 aucune.
5. deploy/azuredeploy.json est a jour et coherent.

Usage : python3 sentinel/tests/test_sentinel.py
"""
import json
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from urllib.parse import unquote

import yaml

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent
TACTICS = {
    "Reconnaissance", "ResourceDevelopment", "InitialAccess", "Execution", "Persistence",
    "PrivilegeEscalation", "DefenseEvasion", "CredentialAccess", "Discovery", "LateralMovement",
    "Collection", "Exfiltration", "CommandAndControl", "Impact",
}
REQUIRED = ["id", "name", "description", "severity", "queryFrequency", "queryPeriod", "triggerOperator",
            "triggerThreshold", "tactics", "relevantTechniques", "query", "entityMappings", "version", "kind"]
ATTACKER, BENIGN = "198.51.100.66", "192.0.2.10"

failures = []


def check(cond, msg):
    if not cond:
        failures.append(msg)


def strip_kql(text):
    """Retire commentaires et chaines ; leve ValueError si une chaine n'est pas fermee."""
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif c == "@" and i + 1 < n and text[i + 1] in "\"'":
            q, i = text[i + 1], i + 2
            while True:
                if i >= n:
                    raise ValueError("chaine verbatim non fermee")
                if text[i] == q:
                    if i + 1 < n and text[i + 1] == q:
                        i += 2
                        continue
                    i += 1
                    break
                i += 1
            out.append('""')
        elif c in "\"'":
            q, i = c, i + 1
            while True:
                if i >= n or text[i] == "\n":
                    raise ValueError("chaine non fermee")
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == q:
                    i += 1
                    break
                i += 1
            out.append('""')
        elif c == "`":  # pas de backtick hors chaine en KQL
            raise ValueError("backtick hors chaine")
        else:
            out.append(c)
            i += 1
    return "".join(out)


def check_kql(name, text):
    try:
        bare = strip_kql(text)
    except ValueError as e:
        check(False, f"{name}: {e}")
        return
    stack, pairs = [], {")": "(", "]": "[", "}": "{"}
    for ch in bare:
        if ch in "([{":
            stack.append(ch)
        elif ch in ")]}":
            if not stack or stack.pop() != pairs[ch]:
                check(False, f"{name}: {ch!r} sans ouverture correspondante")
                return
    check(not stack, f"{name}: {len(stack)} parenthese(s) non fermee(s)")
    for rx in re.findall(r'@"((?:[^"]|"")*)"', text):
        rx = rx.replace('""', '"')
        if any(t in rx for t in ("(?i)", "\\", "|", "^", "$", "{")):
            try:
                re.compile(rx)
            except re.error as e:
                check(False, f"{name}: regex invalide {rx!r}: {e}")


def regex_after(text, marker):
    m = re.search(re.escape(marker) + r'\s*@"((?:[^"]|"")*)"', text)
    assert m, f"regex introuvable apres {marker!r}"
    return re.compile(m.group(1).replace('""', '"'))


# ---------------------------------------------------------------------------- 1 + 2 + 3
rules = {}
for path in sorted((ROOT / "analytics").glob("*.yaml")):
    r = yaml.safe_load(path.read_text(encoding="utf-8"))
    rules[path.stem] = r
    for key in REQUIRED:
        check(key in r, f"{path.name}: champ {key} manquant")
    check(r.get("severity") in {"Informational", "Low", "Medium", "High"}, f"{path.name}: severite invalide")
    check(set(r.get("tactics", [])) <= TACTICS, f"{path.name}: tactique inconnue {r.get('tactics')}")
    check(all(re.fullmatch(r"T\d{4}", t) for t in r.get("relevantTechniques", [])),
          f"{path.name}: technique au format T1234 attendu (sans sous-technique pour l'API 2023-02-01)")
    for em in r.get("entityMappings", []):
        for fm in em["fieldMappings"]:
            check(re.search(r"\b" + fm["columnName"] + r"\b", r["query"]),
                  f"{path.name}: colonne d'entite {fm['columnName']} absente de la requete")
    for col in (r.get("customDetails") or {}).values():
        check(re.search(r"\b" + col + r"\b", r["query"]), f"{path.name}: customDetails {col} absent")
    for col in re.findall(r"\{\{(\w+)\}\}", json.dumps(r.get("alertDetailsOverride", {}))):
        check(re.search(r"\b" + col + r"\b", r["query"]), f"{path.name}: {col} (alertDetailsOverride) absent")
    check_kql(path.name, r["query"])
ids = [r["id"] for r in rules.values()]
check(len(ids) == len(set(ids)), "GUID de regle en double")

for path in list((ROOT / "functions").glob("*.kql")) + list((ROOT / "hunting").glob("*.kql")):
    check_kql(path.name, path.read_text(encoding="utf-8"))
wb = json.loads((ROOT / "workbook" / "artex_workbook.json").read_text(encoding="utf-8"))
for item in wb["items"]:
    if item["type"] == 3:
        check_kql(f"workbook:{item['name']}", item["content"]["query"])

# ---------------------------------------------------------------------------- 4 simulation
parser = (ROOT / "functions" / "ArtexWebRequests.kql").read_text(encoding="utf-8")
combined = regex_after(parser, "extract_all(")
rows = []
for line in (REPO / "samples" / "access_demo.log").read_text().splitlines():
    m = combined.match(line)
    check(m is not None, f"ligne non reconnue par le parseur Syslog : {line[:80]}")
    if not m:
        continue
    ip, method, uri, status, ua = m.groups()
    path, _, query = uri.partition("?")
    rows.append({"SrcIp": ip, "UrlPath": path, "UrlQuery": query, "Url": uri, "Status": int(status),
                 "UserAgent": ua, "Target": uri + " " + unquote(uri)})


def fired(rule_stem, predicate, threshold=1):
    by_ip = defaultdict(int)
    for row in rows:
        if predicate(row):
            by_ip[row["SrcIp"]] += 1
    return {ip for ip, c in by_ip.items() if c >= threshold}


q = {k: v["query"] for k, v in rules.items()}
expect = {
    "01_artex_assessment_user_agent": fired("01", lambda r: r["UserAgent"].startswith("ARTEX-Assessment/")),
    "02_artex_toolchain_user_agents": fired("02", lambda r: any(
        t in r["UserAgent"] for t in ("sqlmap/", "Fuzz Faster U Fool", "Nmap Scripting Engine", "(Hydra)",
                                       "nuclei", "dalfox", "HeadlessChrome"))),
    "03_artex_lfi_traversal": fired("03", lambda r, rx=regex_after(q["03_artex_lfi_traversal"], "matches regex"):
                                    bool(rx.search(r["Target"]))),
    "04_artex_php2shell_session_lfi": fired("04", lambda r: "sess_" in r["Target"]
                                            and re.search(r"(?i)sess_[a-z0-9,-]{6,}", r["Target"])
                                            and re.search(r"(?i)(\.\./|%2e%2e|/tmp/|/var/lib/php)", r["Target"])),
}
sqli = regex_after(q["05_artex_sqli_xss_probes"], "let sqli =")
xss = regex_after(q["05_artex_sqli_xss_probes"], "let xss =")
expect["05_artex_sqli_xss_probes (sans seuil)"] = fired(
    "05", lambda r: bool(r["UrlQuery"]) and bool(sqli.search(r["Target"]) or xss.search(r["Target"])))
# 06 : >= 100 404 sur >= 100 chemins distincts dans la meme tranche de 5 min (le journal dure 24 s)
nf = defaultdict(set)
for r in rows:
    if r["Status"] == 404:
        nf[r["SrcIp"]].add(r["UrlPath"])
expect["06_artex_burst_scan"] = {ip for ip, p in nf.items() if len(p) >= 100}

for name, ips in expect.items():
    check(ATTACKER in ips, f"simulation : {name} ne detecte pas {ATTACKER}")
    check(BENIGN not in ips, f"simulation : {name} declenche sur la source legitime {BENIGN}")

# 07 : score (signatures de la regle, poids comptes une fois)
score_q = q["07_artex_attack_score"]
sigs = re.findall(r'(\w+) = (UserAgent|Target) matches regex @"((?:[^"]|"")*)"', score_q)
weights = dict((v, int(w)) for w, v in re.findall(r"(\d+) \* (\w+)", score_q))
check(len(sigs) == len(weights) == 19, f"score : {len(sigs)} signatures / {len(weights)} poids")
scores = {}
for ip in (ATTACKER, BENIGN):
    mine = [r for r in rows if r["SrcIp"] == ip]
    s = sum(weights[v] for v, col, rx in sigs
            if any(re.search(rx.replace('""', '"'), r[col]) for r in mine))
    paths = {r["UrlPath"] for r in mine}
    e4 = sum(1 for r in mine if 400 <= r["Status"] < 500)
    s += 30 if len(mine) >= 500 else 0
    s += 30 if len(paths) >= 200 and e4 / len(mine) > 0.6 else 0
    s += 20 if len({r["UserAgent"] for r in mine}) >= 5 else 0
    scores[ip] = s
check(scores[ATTACKER] >= 100, f"score attaquant trop bas : {scores[ATTACKER]}")
check(scores[BENIGN] < 30, f"score source legitime trop haut : {scores[BENIGN]}")

# ---------------------------------------------------------------------------- 5 ARM
res = subprocess.run([sys.executable, str(ROOT / "build_arm.py"), "--check"], capture_output=True, text=True)
check(res.returncode == 0, "azuredeploy.json pas a jour : " + res.stderr.strip())
arm = json.loads((ROOT / "deploy" / "azuredeploy.json").read_text(encoding="utf-8"))
kinds = defaultdict(int)
for r in arm["resources"]:
    kinds[r["type"]] += 1
    for v in r.get("properties", {}).values():
        if isinstance(v, str) and v.startswith("[") and not v.endswith("]"):
            check(False, f"ARM : chaine commencant par '[' mal interpretee dans {r['name']}")
check(kinds["Microsoft.OperationalInsights/workspaces/providers/alertRules"] == len(rules), "ARM : regles manquantes")

if failures:
    print("ECHEC :")
    for f in failures:
        print("  -", f)
    sys.exit(1)
print(f"OK : {len(rules)} regles, simulation {ATTACKER} score={scores[ATTACKER]}, {BENIGN} score={scores[BENIGN]}")
