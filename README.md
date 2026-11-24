# ARTEX Blue Team

Kit défensif pour détecter et répondre aux attaques menées avec
[ARTEX](https://github.com/BaaRai/ARTEX), une plateforme de pentest autonome pilotée par LLM.
Tout est en lecture seule et strictement défensif.

## Contenu

| Chemin | Rôle |
|---|---|
| `rules/suricata/artex.rules` | 21 règles réseau (UA ARTEX, en-têtes internes, outils embarqués, php2shell, LFI, callbacks OAST, rafales). Validées avec Suricata 7.0.3. |
| `rules/sigma/*.yml` | 6 règles Sigma (logs web et création de processus), convertibles vers tout SIEM. Validées avec pySigma. |
| `rules/yara/artex.yar` | 3 règles YARA : sessions PHP piégées, webshells, binaire/config ARTEX. Validées avec yara-python. |
| `tools/artex_triage.py` | Script Python (bibliothèque standard) : `logs` pour scorer les IP dans les journaux web, `host` pour chasser les IOC sur un serveur. |
| `playbook/PLAYBOOK.md` | Playbook de réponse (préparation, détection, confinement, éradication, retour d'expérience) avec la cartographie MITRE ATT&CK. |
| `samples/access_demo.log` | Journal synthétique pour tester le script. |
| `sentinel/` | Adaptation à **Microsoft Sentinel** : 11 règles d'analyse KQL, 4 requêtes de chasse, un classeur et un modèle ARM prêt à déployer. Voir [`sentinel/README.md`](sentinel/README.md). |

## Démarrage rapide

```bash
# Tester sur l'exemple
python3 tools/artex_triage.py logs samples/access_demo.log

# Analyser vos journaux et produire un rapport JSON
python3 tools/artex_triage.py logs /var/log/nginx/access.log* --json triage.json

# Chasser les IOC sur un serveur web PHP
sudo python3 tools/artex_triage.py host --webroot /var/www --json host.json

# Règles
suricata -T -S rules/suricata/artex.rules
yara -r rules/yara/artex.yar /var/lib/php/sessions /var/www
sigma convert -t splunk --without-pipeline rules/sigma/   # ou -t lucene, etc.
```

Code de sortie du script : `2` si une source CRITIQUE/ELEVE ou un IOC hôte est trouvé, `0` sinon
(utile en tâche planifiée).

## Ce qu'on sait d'ARTEX (analyse du code, 24/11/2026)

- **Fonctionnement** : planner LLM, workers qui exécutent de vrais outils, proxy MITM qui enregistre
  tout le trafic (port 8788), UI/API sur le port 8787, base PostgreSQL.
- **Outils embarqués** : nmap, subfinder, httpx, katana, ffuf, nuclei (+10 000 templates), dalfox,
  sqlmap 1.9.9, bbot 3.0.2, Playwright/Chromium, hydra, ncrack, hashcat, john, impacket.
- **Identifiants** : UA optionnel `ARTEX-Assessment/1.0 (engagement=…)`, UA `artex-update-check`,
  en-têtes `X-ARTEX-Replay-Nonce`, `X-Artex-Hook`, `X-ARTEX-HAR-*`.
- **Rythme** : profil de bruit `off` par défaut (rafales), sinon `quiet`/`balanced`/`aggressive`.
- **Exploit notable** : `php2shell` (LFI → RCE via `PHP_SESSION_UPLOAD_PROGRESS`).

## Limites

- Un attaquant peut changer les User-Agents et activer le profil `quiet` : les règles
  comportementales (charges, inclusion `sess_*`, OAST, enumération) restent alors le meilleur signal.
- Les UA scanners génériques produisent des faux positifs si vous avez des scanners autorisés :
  ajoutez leurs IP en exception.
- Le contenu HTTPS n'est visible par Suricata qu'après terminaison TLS (reverse proxy, WAF).
