# Déploiement et passage en production

## 1. Observer en dry-run (au moins une à deux semaines)

1. `cp .env.example .env`, définir une vraie `SOAR_API_KEY`, `docker compose up -d --build`.
2. Brancher les sources (section 4). Laisser `mode: dry_run`.
3. Remplir `guard.protected_networks` (passerelles, DNS, supervision, VPN admin, l'hôte du SOAR),
   `authorized_sources` / `authorized_engagements` (pentests prévus) et `inventory.hosts`.
4. Relire chaque jour les actions `dry_run` du tableau de bord : un blocage simulé sur une IP
   légitime = ajuster la configuration (exception, seuil `min_score`, playbook).

## 2. Préparer le pare-feu de l'hôte (une seule fois)

nftables :

```bash
nft add table inet filter
nft add chain inet filter input '{ type filter hook input priority 0; policy accept; }'
nft add set inet filter artex_soar_block  '{ type ipv4_addr; flags timeout; }'
nft add set inet filter artex_soar_block6 '{ type ipv6_addr; flags timeout; }'
nft add rule inet filter input ip  saddr @artex_soar_block  drop
nft add rule inet filter input ip6 saddr @artex_soar_block6 drop
```

ipset/iptables : `ipset create artex_soar_block hash:ip timeout 0` puis
`iptables -I INPUT -m set --match-set artex_soar_block src -j DROP`.

Les blocages expirent tout seuls (timeout du set). Pour débloquer à la main :
`nft delete element inet filter artex_soar_block '{ 198.51.100.66 }'`.

Liste nginx : `include /chemin/vers/data/blocklist/artex_deny.conf;` dans le bloc `http` ou
`server`, et `reload_command: ["nginx", "-s", "reload"]` si le SOAR tourne sur le même hôte.

## 3. Passer en enforce, connecteur par connecteur

1. Dans `config/soar.yml`, mettre `dry_run: false` uniquement sur le connecteur validé
   (ex. `nginx_deny`), puis `SOAR_MODE=enforce` dans `.env`.
2. Pour nftables/ipset depuis le conteneur, décommenter dans `docker-compose.yml` :
   `network_mode: host`, `cap_add: [NET_ADMIN]`, `user: root`. Alternative : lancer le SOAR
   directement sur l'hôte (`pip install -r requirements.txt && python -m artex_soar serve`).
3. Isolation : écrire le script `/usr/local/bin/soar-isolate-host` (ou un playbook Ansible, un
   appel à votre EDR) qui met **votre** serveur en quarantaine réseau tout en gardant l'accès
   console. Elle reste soumise à approbation.
4. `GET /health` affiche pour chaque connecteur s'il est encore en dry-run.

## 4. Brancher les sources

| Source | Méthode |
|---|---|
| nginx/Apache | `docker compose --profile shipper up -d` (variables `NGINX_LOG_DIR`, `SOAR_TARGET`), ou `python -m artex_soar ship /var/log/nginx/access.log --target web01` sur chaque serveur. |
| Suricata | `python -m artex_soar ship /var/log/suricata/eve.json --format eve`, avec `rules/suricata/artex.rules` chargées. |
| Chasse hôte | cron horaire : `artex_triage.py host --webroot /var/www --json /tmp/h.json; curl -X POST -H "X-API-Key: …" -H "Content-Type: application/json" --data @/tmp/h.json http://soar:8080/api/v1/ingest/triage` |
| SIEM / WAF | règle d'alerte qui POST des événements normalisés sur `/api/v1/events`. |

## 5. Notifications

Décommenter `chat` (webhook Slack/Teams/Mattermost, URL dans `SOAR_WEBHOOK_URL`) ou `mail`
dans `config/soar.yml`, puis les ajouter aux actions `notify` des playbooks.

## 6. Exploitation

- Sauvegarder le volume `soar-data` (base SQLite, tickets, preuves avec manifeste SHA-256).
- Ne jamais exposer l'API sur Internet : le port est lié à `127.0.0.1` par défaut. Pour un accès
  distant, passer par un reverse proxy TLS avec authentification.
- Après un incident P1, suivre les sections 4 à 6 de `playbook/PLAYBOOK.md` (éradication,
  restauration, retour d'expérience).
