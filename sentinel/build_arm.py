#!/usr/bin/env python3
"""Construit deploy/azuredeploy.json (modele ARM) a partir des fichiers du dossier sentinel/.

Sources :
  functions/*.kql   -> fonctions Log Analytics (alias = nom du fichier)
  analytics/*.yaml  -> regles d'analyse planifiees Microsoft Sentinel
  hunting/*.kql     -> requetes de chasse Microsoft Sentinel
  workbook/artex_workbook.json -> classeur (workbook)

Usage : python3 sentinel/build_arm.py        (necessite PyYAML)
        python3 sentinel/build_arm.py --check (echoue si azuredeploy.json n'est pas a jour)
"""
import json
import re
import sys
import uuid
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "deploy" / "azuredeploy.json"
NS = uuid.UUID("6a1e0c0d-a7e5-4b1e-9001-000000000000")  # espace de noms des GUID stables

TRIGGER_OPS = {"gt": "GreaterThan", "lt": "LessThan", "eq": "Equal", "ne": "NotEqual"}


def iso_duration(value):
    """'15m' -> 'PT15M', '6h' -> 'PT6H', '1d' -> 'P1D'."""
    m = re.fullmatch(r"(\d+)([mhd])", str(value).strip())
    if not m:
        raise ValueError(f"duree invalide : {value!r}")
    n, unit = m.groups()
    return f"P{n}D" if unit == "d" else f"PT{n}{unit.upper()}"


def workspace_child(type_, name_expr):
    return f"[concat(parameters('workspace'), '/{type_}', {name_expr})]"


def function_resource(path):
    alias = path.stem
    return {
        "type": "Microsoft.OperationalInsights/workspaces/savedSearches",
        "apiVersion": "2020-08-01",
        "name": f"[concat(parameters('workspace'), '/{alias}')]",
        "properties": {
            "category": "ARTEX Blue Team",
            "displayName": alias,
            "functionAlias": alias,
            "query": path.read_text(encoding="utf-8"),
            "version": 2,
        },
    }


def hunting_resource(path):
    text = path.read_text(encoding="utf-8")
    title = re.search(r"^// Titre : (.+)$", text, re.M).group(1).strip()
    tactic = re.search(r"^// Tactique : (\w+)", text, re.M).group(1)
    techniques = re.findall(r"T\d{4}", re.search(r"^// Tactique : (.+)$", text, re.M).group(1))
    desc = " ".join(
        line[3:].strip() for line in text.splitlines()
        if line.startswith("// ") and not line.startswith(("// Titre", "// Tactique"))
    )
    name = f"artex-hunt-{path.stem.replace('_', '-')}"
    return {
        "type": "Microsoft.OperationalInsights/workspaces/savedSearches",
        "apiVersion": "2020-08-01",
        "name": f"[concat(parameters('workspace'), '/{name}')]",
        "dependsOn": ["[variables('fnWeb')]", "[variables('fnAllow')]"],
        "properties": {
            "category": "Hunting Queries",
            "displayName": title,
            "query": text,
            "version": 2,
            "tags": [
                {"name": "description", "value": desc},
                {"name": "tactics", "value": tactic},
                {"name": "techniques", "value": ",".join(techniques)},
            ],
        },
    }


def rule_resource(path):
    r = yaml.safe_load(path.read_text(encoding="utf-8"))
    props = {
        "displayName": r["name"],
        "description": r["description"].strip(),
        "severity": r["severity"],
        "enabled": "[parameters('enableRules')]",
        "query": r["query"],
        "queryFrequency": iso_duration(r["queryFrequency"]),
        "queryPeriod": iso_duration(r["queryPeriod"]),
        "triggerOperator": TRIGGER_OPS[r["triggerOperator"]],
        "triggerThreshold": r["triggerThreshold"],
        "suppressionDuration": "PT5H",
        "suppressionEnabled": False,
        "tactics": r["tactics"],
        "techniques": r["relevantTechniques"],
        "entityMappings": r.get("entityMappings", []),
        "eventGroupingSettings": r.get("eventGroupingSettings", {"aggregationKind": "SingleAlert"}),
    }
    if r.get("customDetails"):
        props["customDetails"] = r["customDetails"]
    if r.get("alertDetailsOverride"):
        props["alertDetailsOverride"] = r["alertDetailsOverride"]
    inc = r.get("incidentConfiguration")
    if inc:
        grp = dict(inc.get("groupingConfiguration", {}))
        if "lookbackDuration" in grp:
            grp["lookbackDuration"] = iso_duration(grp["lookbackDuration"])
        props["incidentConfiguration"] = {
            "createIncident": "[parameters('createIncidents')]",
            "groupingConfiguration": grp,
        }
    return {
        "type": "Microsoft.OperationalInsights/workspaces/providers/alertRules",
        "apiVersion": "2023-02-01",
        "name": workspace_child("Microsoft.SecurityInsights/", f"'{r['id']}'"),
        "kind": "Scheduled",
        "dependsOn": ["[variables('fnWeb')]", "[variables('fnAllow')]"],
        "properties": props,
    }


def workbook_resource(path):
    return {
        "condition": "[parameters('deployWorkbook')]",
        "type": "Microsoft.Insights/workbooks",
        "apiVersion": "2022-04-01",
        "name": str(uuid.uuid5(NS, "artex-workbook")),
        "location": "[resourceGroup().location]",
        "kind": "shared",
        "dependsOn": ["[variables('fnWeb')]", "[variables('fnAllow')]"],
        "properties": {
            "displayName": "ARTEX - Vue d'ensemble",
            "serializedData": json.dumps(json.loads(path.read_text(encoding="utf-8")), ensure_ascii=False),
            "version": "1.0",
            "sourceId": "[resourceId('Microsoft.OperationalInsights/workspaces', parameters('workspace'))]",
            "category": "sentinel",
        },
    }


def build():
    resources = [function_resource(p) for p in sorted((ROOT / "functions").glob("*.kql"))]
    resources += [rule_resource(p) for p in sorted((ROOT / "analytics").glob("*.yaml"))]
    resources += [hunting_resource(p) for p in sorted((ROOT / "hunting").glob("*.kql"))]
    resources.append(workbook_resource(ROOT / "workbook" / "artex_workbook.json"))
    return {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "metadata": {
            "description": "Kit ARTEX Blue Team pour Microsoft Sentinel. Fichier genere par sentinel/build_arm.py : ne pas modifier a la main.",
        },
        "parameters": {
            "workspace": {
                "type": "string",
                "metadata": {"description": "Nom de l'espace de travail Log Analytics ou Microsoft Sentinel est active."},
            },
            "enableRules": {
                "type": "bool",
                "defaultValue": True,
                "metadata": {"description": "Activer les regles d'analyse des leur creation."},
            },
            "createIncidents": {
                "type": "bool",
                "defaultValue": True,
                "metadata": {"description": "Creer un incident pour chaque alerte (sinon : alertes seules)."},
            },
            "deployWorkbook": {
                "type": "bool",
                "defaultValue": True,
                "metadata": {"description": "Deployer le classeur 'ARTEX - Vue d'ensemble'."},
            },
        },
        "variables": {
            "fnWeb": "[resourceId('Microsoft.OperationalInsights/workspaces/savedSearches', parameters('workspace'), 'ArtexWebRequests')]",
            "fnAllow": "[resourceId('Microsoft.OperationalInsights/workspaces/savedSearches', parameters('workspace'), 'ArtexAllowlist')]",
        },
        "resources": resources,
    }


def main():
    content = json.dumps(build(), indent=2, ensure_ascii=False) + "\n"
    if "--check" in sys.argv:
        if not OUT.exists() or OUT.read_text(encoding="utf-8") != content:
            print("deploy/azuredeploy.json n'est pas a jour : lancez python3 sentinel/build_arm.py", file=sys.stderr)
            return 1
        print("deploy/azuredeploy.json est a jour")
        return 0
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(content, encoding="utf-8")
    print(f"{OUT.relative_to(ROOT.parent)} genere ({len(build()['resources'])} ressources)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
