"""Chargement de la configuration YAML (avec valeurs par defaut sures)."""
import copy
import os
from typing import Any, Dict

import yaml

DEFAULTS: Dict[str, Any] = {
    # dry_run : aucune action perturbatrice (blocage, isolation) n'est executee pour de vrai,
    # meme apres approbation. Passer a "enforce" uniquement apres validation.
    "mode": "dry_run",
    "database": "data/soar.db",
    "detection": {
        "min_score": 30,             # score minimal pour ouvrir un incident
        "burst_threshold": 50,       # requetes / 10 s
        "incident_timeout": 3600,    # secondes d'inactivite avant d'ouvrir un nouvel incident
        "max_tracked_sources": 100000,
        "home_networks": [],         # vos reseaux (ex. 10.0.0.0/8) pour reconnaitre le trafic sortant
    },
    "guard": {
        # Jamais bloquees : vos propres equipements, la supervision, le SOAR lui-meme.
        "protected_networks": ["127.0.0.0/8", "::1/128", "169.254.0.0/16", "fe80::/10"],
        # Pentests autorises : les incidents sont marques "authorized", seules les
        # notifications partent.
        "authorized_sources": [],
        "authorized_engagements": [],
        # Au-dela, chaque nouveau blocage attend une approbation humaine.
        "max_blocks_per_hour": 50,
    },
    # Serveurs de VOTRE infrastructure que le SOAR peut isoler (apres approbation).
    "inventory": {"hosts": []},
    "connectors": {
        "log": {"type": "log", "path": "data/notifications.log"},
        "ticket": {"type": "ticket_file", "directory": "data/tickets"},
        "evidence": {"type": "evidence", "directory": "data/evidence"},
        "nftables": {"type": "nftables", "dry_run": True},
    },
    "playbooks_file": "config/playbooks.yml",
    "playbooks": [],
}


def _merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict) and k != "connectors":
            out[k] = _merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def load_config(path: str = None) -> Dict[str, Any]:
    path = path or os.environ.get("SOAR_CONFIG", "config/soar.yml")
    if not os.path.isfile(path) and not os.path.isabs(path):
        # Repli : configuration livree a cote du paquet (soar/config/...)
        alt = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), path)
        if os.path.isfile(alt):
            path = alt
    data: Dict[str, Any] = {}
    base_dir = os.getcwd()
    if path and os.path.isfile(path):
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(path))) or base_dir
    cfg = _merge(DEFAULTS, data)
    if os.environ.get("SOAR_MODE"):
        cfg["mode"] = os.environ["SOAR_MODE"]
    if cfg["mode"] not in ("dry_run", "enforce"):
        raise ValueError("mode doit valoir 'dry_run' ou 'enforce'")
    if not cfg.get("playbooks"):
        pb = cfg.get("playbooks_file")
        if pb and not os.path.isabs(pb):
            pb = os.path.join(base_dir, pb)
        if pb and os.path.isfile(pb):
            with open(pb) as f:
                cfg["playbooks"] = (yaml.safe_load(f) or {}).get("playbooks", [])
    cfg["_base_dir"] = base_dir
    return cfg


def resolve(cfg: Dict[str, Any], path: str) -> str:
    """Chemin relatif -> relatif au dossier racine du SOAR."""
    return path if os.path.isabs(path) else os.path.join(cfg.get("_base_dir", "."), path)
