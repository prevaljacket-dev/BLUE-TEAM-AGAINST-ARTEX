# Kit ARTEX pour Microsoft Sentinel

Ce dossier adapte le kit blue team ARTEX à **Microsoft Sentinel** : 11 règles d'analyse KQL, 4 requêtes
de chasse, un classeur (workbook) et un modèle ARM qui déploie tout en une fois.

## Ce qui est déployé

| Élément | Nombre | Où le voir dans Sentinel |
|---|---|---|
| Fonctions KQL `ArtexWebRequests` et `ArtexAllowlist` | 2 | Logs > Fonctions > ARTEX Blue Team |
| Règles d'analyse planifiées (créent des incidents) | 11 | Configuration > Analytique |
| Requêtes de chasse | 4 | Gestion des menaces > Chasse |
| Classeur « ARTEX - Vue d'ensemble » | 1 | Gestion des menaces > Classeurs > Mes classeurs |

### Les règles

| # | Règle | Gravité | Fréquence | Équivalent dans le kit |
|---|---|---|---|---|
| 01 | User-Agent `ARTEX-Assessment` | Élevée | 1 h | Sigma `artex_assessment_user_agent`, SID 9100001 |
| 02 | User-Agents des outils embarqués (sqlmap, ffuf, nmap, hydra, nuclei, dalfox, headless) | Moyenne | 1 h | Sigma `artex_toolchain_user_agents`, SID 9100020-25 |
| 03 | LFI / traversée de répertoire | Élevée | 1 h | Sigma `artex_lfi_traversal`, SID 9100050 |
| 04 | **php2shell** : inclusion d'un fichier `sess_*` | Élevée | 15 min | Sigma `artex_php2shell_session_lfi`, SID 9100040-42 |
| 05 | Sondes SQLi / XSS (≥ 3 par IP) | Moyenne | 1 h | Sigma `artex_sqli_xss_probes` |
| 06 | Rafale ou énumération massive (404) | Moyenne | 1 h | SID 9100060 |
| 07 | **Score d'attaque par IP** (même calcul que `artex_triage.py`, alerte ≥ 100) | Élevée | 1 h sur 6 h | `tools/artex_triage.py logs` |
| 08 | Instance ARTEX lancée sur un hôte interne | Élevée | 1 h | Sigma `artex_instance_on_host` |
| 09 | Callback OAST (`*.oast.*`, `*.interact.sh`) depuis un serveur | Élevée | 1 h | SID 9100030-31 |
| 10 | Alertes Suricata du kit remontées dans Sentinel | Moyenne | 1 h | `rules/suricata/artex.rules` |
| 11 | `artex-update-check` : instance ARTEX dans votre réseau | Moyenne | 1 h | SID 9100002 |

Les règles YARA restent à lancer sur les serveurs (voir le playbook) : Sentinel ne lit pas le contenu
des fichiers.

## Sources de logs prises en charge

Toutes les règles web (01 à 07, 11) passent par la fonction **`ArtexWebRequests`**, qui rassemble
les requêtes HTTP de toutes les sources présentes dans votre espace de travail. **Une source absente
est simplement ignorée** : rien à modifier si vous n'avez que IIS, ou que l'Application Gateway.

| Source | Table Sentinel | Utilisée par |
|---|---|---|
| IIS (agent Azure Monitor) | `W3CIISLog` | règles web |
| Application Gateway / WAF v2 | `AzureDiagnostics` (ApplicationGatewayAccessLog) ou `AGWAccessLogs` | règles web |
| Azure Front Door | `AzureDiagnostics` (FrontDoorAccessLog) | règles web |
| Pare-feu, WAF ou proxy en CEF (Fortinet, Palo Alto, F5, Imperva, Barracuda, Zscaler…) | `CommonSecurityLog` | règles web, 10, 11 |
| Nginx / Apache envoyés en Syslog (format `combined`) | `Syslog` | règles web |
| Microsoft Defender for Endpoint | `DeviceProcessEvents`, `DeviceNetworkEvents` | 08, 09, chasse |
| Événements Windows 4688 | `SecurityEvent` | 08 |
| DNS Windows / ASIM | `DnsEvents`, `ASimDnsActivityLogs` | 09 |
| Suricata (sortie syslog ou CEF) | `Syslog`, `CommonSecurityLog` | 10 |

Vos logs nginx arrivent dans une **table personnalisée** (par exemple `nginx_CL` via une règle de
collecte) ? Ajoutez une branche dans `functions/ArtexWebRequests.kql` qui produit les mêmes colonnes
(`TimeGenerated, SrcIp, Method, Host, UrlPath, UrlQuery, UserAgent, Status, Computer, LogSource`),
puis redéployez. Aucune règle n'est à toucher.

## Déployer

Il vous faut : un espace de travail Log Analytics avec Microsoft Sentinel activé, et le rôle
**Contributeur Microsoft Sentinel** (ou Contributeur) sur son groupe de ressources.

### Option 1 : depuis le portail Azure (le plus simple)

1. Téléchargez [`deploy/azuredeploy.json`](deploy/azuredeploy.json).
2. Dans le portail Azure, cherchez **« Déployer un modèle personnalisé »** (Deploy a custom template).
3. Cliquez **« Créer votre propre modèle dans l'éditeur »**, puis **« Charger le fichier »** et
   choisissez `azuredeploy.json`. Cliquez **Enregistrer**.
4. Choisissez le **groupe de ressources** de votre espace Sentinel et tapez le **nom de l'espace de
   travail** (champ `Workspace`). Laissez les autres valeurs par défaut.
5. **Vérifier + créer**, puis **Créer**. Le déploiement prend environ une minute.

### Option 2 : Azure CLI

```bash
az deployment group create \
  --resource-group <groupe-de-ressources-sentinel> \
  --template-file sentinel/deploy/azuredeploy.json \
  --parameters workspace=<nom-de-l-espace-de-travail>
```

### Option 3 : PowerShell

```powershell
New-AzResourceGroupDeployment -ResourceGroupName <groupe> `
  -TemplateFile sentinel/deploy/azuredeploy.json -workspace <espace-de-travail>
```

Paramètres optionnels : `enableRules` (activer les règles tout de suite, `true` par défaut),
`createIncidents` (`true` par défaut), `deployWorkbook` (`true` par défaut).

## Après le déploiement

1. **Déclarer les IP autorisées.** Créez une watchlist (Configuration > Watchlist > Nouveau) :
   - Nom et alias : `ArtexAllowlist`
   - Fichier CSV avec une colonne `SrcIp`, une IP par ligne (pentesteurs annoncés, scanners internes)
   - Clé de recherche : `SrcIp`

   Tant qu'elle n'existe pas, les règles fonctionnent sans exception.
2. **Vérifier que vos logs sont reconnus.** Dans Logs, lancez :
   ```kusto
   ArtexWebRequests
   | where TimeGenerated > ago(1d)
   | summarize Requetes = count() by LogSource
   ```
   Chaque source web que vous ingérez doit apparaître. Si une source manque, voir la section
   précédente.
3. **Ajuster les seuils** si besoin : `seuil` (règle 05), `seuilRequetes` / `seuil404` (règle 06),
   `seuilScore` (règle 07) sont des `let` en tête de requête, modifiables dans Configuration >
   Analytique > (règle) > Modifier.
4. Ouvrir le classeur **ARTEX - Vue d'ensemble** pour voir l'activité, puis suivre
   [`playbook/PLAYBOOK.md`](../playbook/PLAYBOOK.md) quand un incident arrive.

## Modifier le contenu

Les fichiers sources sont `functions/*.kql`, `analytics/*.yaml` (format des règles du dépôt
communautaire Azure-Sentinel), `hunting/*.kql` et `workbook/artex_workbook.json`. Le modèle ARM est
**généré** à partir d'eux :

```bash
pip install pyyaml
python3 sentinel/build_arm.py          # régénère deploy/azuredeploy.json
python3 sentinel/tests/test_sentinel.py  # contrôles hors ligne
```

Les tests vérifient la structure des règles, la syntaxe KQL de base (parenthèses, chaînes), les
expressions régulières, et simulent les règles web sur `samples/access_demo.log` : l'attaquant
`198.51.100.66` doit déclencher les règles 01 à 07 (score 450), la source légitime `192.0.2.10` aucune.

## Limites

- Les requêtes n'ont pas encore été exécutées dans un vrai espace Sentinel : les tests sont hors
  ligne. Au premier déploiement, si une règle est refusée (« Failed to resolve… »), relancez le
  déploiement une fois (les fonctions peuvent mettre quelques secondes à être visibles), puis
  signalez l'erreur.
- Les en-têtes `X-ARTEX-*` et le corps des requêtes (`PHP_SESSION_UPLOAD_PROGRESS`) ne figurent pas
  dans les logs web classiques : ils ne sont détectés que par Suricata (règle 10).
- Pour l'Application Gateway, `ClientIp` est l'IP du client direct : si un CDN est devant, c'est l'IP
  du CDN.
- Les limites générales du kit s'appliquent (User-Agents modifiables, profil `quiet`) : la règle 07
  et la chasse `artex_slow_scan` restent les meilleurs signaux dans ce cas.
