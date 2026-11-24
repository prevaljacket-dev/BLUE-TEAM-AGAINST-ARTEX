# Playbook de réponse à incident : attaque menée avec ARTEX

## 0. Comprendre l'adversaire

ARTEX est une plateforme de pentest autonome pilotée par LLM. Un « planner » découpe un objectif
en intentions, des « workers » exécutent de vrais outils, puis le résultat relance le planner.
Conséquences pour la défense :

- **Vitesse** : reconnaissance, scan et exploitation peuvent s'enchaîner en quelques minutes.
- **Outillage connu** : nmap, subfinder, httpx, katana, ffuf, nuclei, dalfox, sqlmap, bbot,
  hydra/ncrack, Playwright (Chromium headless), impacket.
- **Bruit variable** : par défaut aucune limitation (rafales). En profil `quiet`, ~2 req/s par
  hôte, nmap `-T2` : plus discret, à repérer sur la durée.
- **Chaînes d'attaque mémorisées** : il garde une todolist par tâche (injection, identifiants,
  mouvement latéral) et reprend là où il s'est arrêté.
- **Exploit embarqué notable** : `php2shell`, qui transforme une LFI PHP en exécution de code via
  `PHP_SESSION_UPLOAD_PROGRESS` puis l'inclusion du fichier `sess_*`.

| Phase | Techniques ATT&CK | Traces principales |
|---|---|---|
| Reconnaissance | T1595.001/.002/.003, T1590, T1593 | rafales, 404 massifs, UA ffuf / Nmap NSE / HeadlessChrome, DNS de sous-domaines |
| Accès initial | T1190 | SQLi (sqlmap), XSS (dalfox), LFI, callbacks OAST (`*.oast.*`, `interact.sh`) |
| Exécution | T1059.004 | fichiers `sess_*` contenant `<?php`, webshell, processus enfant du serveur web |
| Accès aux identifiants | T1110, T1003 | brute force SSH/HTTP (UA `(Hydra)`), impacket |
| Mouvement latéral | T1021 | connexions SMB/SSH internes depuis le serveur web |
| Infrastructure | T1588.002 | instance ARTEX interne : ports 8787/8788, image `ghcr.io/baarai/artex` |

## 1. Préparation (avant l'incident)

1. Déployer `rules/suricata/artex.rules` sur l'IDS en bordure des serveurs web (SID 9100001-9100060).
2. Convertir `rules/sigma/*.yml` vers votre SIEM (`sigma convert -t splunk|elasticsearch|...`).
   Pour **Microsoft Sentinel**, déployer directement `sentinel/deploy/azuredeploy.json`
   (règles KQL, chasse, classeur) : voir `sentinel/README.md`.
3. Planifier `tools/artex_triage.py logs` toutes les heures sur les journaux d'accès.
4. Durcir PHP : `session.upload_progress.enabled = 0` si inutile, PHP ≥ 8.2.35 / 8.3.36 / 8.4.27 /
   8.5.12, `open_basedir`, `allow_url_include = Off`, et un répertoire de sessions hors de portée
   des inclusions.
5. Activer la limitation de débit (WAF / reverse proxy) : 429 au-delà de ~20 req/s par IP. ARTEX
   ralentit de lui-même sur 429/503 en profil actif.
6. Tenir la liste des pentests autorisés (dates, IP sources, référence `engagement=`) pour
   écarter vite les faux positifs.

## 2. Détection et qualification

**Déclencheurs** : alerte Suricata/Sigma ARTEX, score `CRITIQUE`/`ELEVE` du script, pic de 404,
WAF saturé.

1. Lancer le triage sur la fenêtre concernée :
   ```bash
   python3 tools/artex_triage.py logs /var/log/nginx/access.log* --json triage.json
   ```
2. Vérifier s'il s'agit d'un test autorisé : UA `ARTEX-Assessment/1.0 (engagement=REF)`, IP connue
   de l'équipe offensive. **Si autorisé et dans le périmètre, clore en faux positif documenté.**
3. Sinon, qualifier la gravité :
   - **P3** : reconnaissance seule (UA scanners, 404, aucune charge réussie).
   - **P2** : charges d'exploitation (SQLi/XSS/LFI) avec réponses 200 ou 500 suspectes.
   - **P1** : signe de réussite : inclusion `sess_*` en 200, webshell trouvé, processus enfant
     anormal du serveur web, callback OAST sortant depuis vos serveurs.

## 3. Confinement

**P3/P2**
- Bloquer les IP sources au WAF / pare-feu (fichier `triage.json`, champ `ip`).
- Activer le rate limiting strict sur les vhosts ciblés.
- Passer les SID 9100040-9100042 et 9100050 en `drop` si l'IPS le permet.

**P1 (compromission probable)**
- Isoler le serveur au niveau réseau (garder l'accès console pour l'investigation).
- **Avant toute modification**, collecter les preuves :
  ```bash
  sudo python3 tools/artex_triage.py host --webroot /var/www --json host_$(hostname).json
  yara -r rules/yara/artex.yar /var/lib/php/sessions /tmp /var/www > yara_$(hostname).txt
  ```
  Ajouter : copie des journaux web et système, `ps auxf`, `ss -tanp`, crontab, liste des
  utilisateurs, image mémoire si l'outillage est disponible.
- Bloquer la sortie vers `*.oast.*` et `*.interact.sh` au DNS / proxy.
- Faire tourner les secrets accessibles depuis le serveur (base de données, clés API, `.env`).

## 4. Éradication

1. Supprimer les fichiers `sess_*` piégés et les webshells identifiés (après collecte des preuves).
2. Corriger la vulnérabilité exploitée (paramètre LFI, requête SQL, sortie non échappée).
3. Mettre à jour PHP et désactiver `session.upload_progress` si non utilisé.
4. Rechercher la persistance : crontab, `authorized_keys`, services systemd, fichiers PHP modifiés
   récemment (`--days`).
5. Si une **instance ARTEX** est trouvée chez vous (ports 8787/8788, processus `artex`, conteneur
   `ghcr.io/baarai/artex`) sans autorisation : la traiter comme une infrastructure d'attaque
   interne, identifier le compte qui l'a lancée, conserver sa base PostgreSQL (elle contient les
   tâches, cibles et findings de l'attaquant : précieux pour mesurer l'étendue).

## 5. Rétablissement

- Restaurer depuis une source saine si l'intégrité est douteuse.
- Remettre en service sous surveillance renforcée (seuils de rafale abaissés à 20 req/10 s pendant 14 jours).
- Vérifier qu'aucune nouvelle alerte ARTEX n'apparaît sur 72 h.

## 6. Retour d'expérience

- Chronologie complète (le champ `debut`/`fin` du triage donne la fenêtre d'attaque).
- Quelles vulnérabilités ARTEX a-t-il trouvées ? Le faire tourner en interne (équipe red team
  autorisée) sur les mêmes cibles peut révéler ce que l'attaquant a vu.
- Ajuster les règles (faux positifs, nouveaux UA) et partager les IOC.
