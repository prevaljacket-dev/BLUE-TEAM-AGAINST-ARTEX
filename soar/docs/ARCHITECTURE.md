# Architecture d'ARTEX SOAR

```
 journaux nginx/Apache ─┐
 Suricata EVE ──────────┤   ┌──────────┐   ┌───────────┐   ┌─────────────┐   ┌────────────┐
 artex_triage.py JSON ──┼──▶│ parsers  │──▶│ détection │──▶│ corrélation │──▶│ playbooks  │
 SIEM / WAF (JSON) ─────┘   └──────────┘   └───────────┘   └─────────────┘   └─────┬──────┘
        ▲                                                                           │
   ship (agent)                                                   garde-fous (guard) │
                                                                                     ▼
                                     ┌──────────── connecteurs (dry-run par défaut) ─────────┐
                                     │ nftables · ipset · blocklist_file · command (isolation)│
                                     │ evidence · ticket_file · log · webhook · email         │
                                     └────────────────────────────────────────────────────────┘
                      SQLite : incidents, actions, audit      API REST + tableau de bord
```

## Modules (`artex_soar/`)

| Module | Rôle |
|---|---|
| `signatures.py` | Charge `tools/artex_triage.py` et réutilise ses signatures (pas de copie). Ajoute les identifiants ARTEX et l'étape de chaîne d'attaque. |
| `parsers.py` | Convertit chaque format en `Event` normalisé. |
| `detection.py` | `analyse_event` (constats ponctuels) et `SourceTracker` (signaux comportementaux, pool LRU borné). |
| `engine.py` | Corrélation en incidents, qualification, exécution des playbooks, approbations. |
| `guard.py` | Garde-fous : réseaux protégés, pentests autorisés, plafond de blocages, inventaire. |
| `connectors/` | Actions enfichables (voir ci-dessous). |
| `store.py` | Persistance SQLite (thread-safe). |
| `api.py`, `dashboard.html` | API FastAPI et tableau de bord sans dépendance externe. |
| `cli.py` | `serve`, `replay` (hors ligne, toujours en simulation), `ship` (agent de suivi de journal). |

## Événement normalisé (`POST /api/v1/events`)

```json
{"ts": "2026-11-24T10:00:00Z", "kind": "http", "source_ip": "198.51.100.66",
 "target": "web01", "sensor": "waf", "method": "GET", "uri": "/view.php?file=../../etc/passwd",
 "status": 200, "user_agent": "...", "headers": {"X-Artex-Hook": "1"},
 "signature": "", "signature_id": null}
```

`kind` : `http`, `ids`, `host` (IOC sur un serveur, `target` obligatoire), `auth` (échec
d'authentification, 20 échecs = brute force).

## Qualification (alignée sur `playbook/PLAYBOOK.md`)

- **Score** : somme des poids des indicateurs distincts (mêmes poids que `artex_triage.py`).
  Un incident s'ouvre à `min_score` (30 par défaut).
- **P3** : reconnaissance (UA d'outils, 404 massifs, rafales).
- **P2** : charge d'exploitation ayant reçu une réponse 2xx/5xx, alerte IDS aboutie, ou brute force.
- **P1** : inclusion de session PHP (`sess_*`) aboutie (php2shell), ou IOC sur un serveur
  (session piégée, webshell, processus ARTEX), ce qui escalade aussi les sources qui ont visé ce serveur.
- **ARTEX confirmé** : UA `ARTEX-Assessment/`, en-têtes `X-ARTEX-*`, SID 9100001-9100019.
- La gravité ne redescend jamais. Après `incident_timeout` secondes d'inactivité, ou si
  l'incident est clos, une nouvelle activité ouvre un nouvel incident.

## Cycle de vie d'une action

`pending_approval` → (`approve`) → `done` | `dry_run` | `failed`, ou `rejected`.
`blocked_by_guard` si un garde-fou refuse. Chaque action d'un playbook ne part qu'une fois par incident.

## Écrire un connecteur

```python
from artex_soar.connectors.base import Connector
from artex_soar.models import ActionResult

class MonWafConnector(Connector):
    disruptive = True               # => dry-run tant que mode != enforce ou dry_run: true
    supports = ("block_ip",)

    def run(self, action_type, params, incident, dry_run):
        ip = incident["source_ip"]
        if dry_run:
            return ActionResult(True, True, f"simulation : {ip} serait bloquée sur le WAF")
        ...  # appel à l'API de VOTRE WAF
        return ActionResult(True, False, f"{ip} bloquée")
```

Puis l'ajouter à `REGISTRY` dans `connectors/__init__.py`, le déclarer dans `config/soar.yml`
et l'utiliser dans un playbook. Règle du projet : un connecteur n'agit que sur votre
infrastructure (pare-feu, WAF, serveurs, outils internes). Pas de scan, pas de contact avec la source.
