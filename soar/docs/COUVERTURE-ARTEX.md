# Couverture ARTEX : attaque, détection, réponse

Ce tableau recense ce qu'ARTEX sait faire, d'après ses compétences et les outils embarqués dans
son image. Pour chaque attaque, il indique comment ARTEX SOAR la voit et ce qu'il fait.

**Légende de la réponse.** Les playbooks de `config/playbooks.yml` décident de la réponse selon la
gravité :

- **Faible (P3), score de 60 ou plus** : notification et ticket.
- **ARTEX confirmé** (signature propre à ARTEX) : blocage de l'IP sur le pare-feu et le WAF.
- **Moyenne (P2)**, dès qu'il y a exploitation : ticket, blocage d'une semaine et alerte.
- **Élevée (P1)**, compromission constatée : collecte de preuves, alerte, puis isolation du serveur
  touché **après ton approbation**.

Toutes les actions visent ton infrastructure. Le SOAR ne contacte jamais l'attaquant.

## A. Reconnaissance

| # | Attaque ARTEX (outil) | Ce que le SOAR détecte | Source à brancher | Réponse |
|---|---|---|---|---|
| 1 | Sous-domaines et OSINT passifs (subfinder, bbot passif) | **Rien** : ARTEX ne touche pas tes serveurs | aucune | Réduire la surface : DNS propre, pas de sous-domaines oubliés |
| 2 | Résolution et force brute DNS (dnsx, bbot actif) | Alerte IDS si Suricata surveille ton DNS | Suricata EVE | Notification ; blocage si ARTEX est confirmé |
| 3 | Découverte du réseau local (arp-scan, netdiscover, fping) | Alertes IDS (balayage ARP ou ICMP) | Suricata EVE | Notification et ticket |
| 4 | Scan de ports et de services (nmap, ssh-audit) | « Scan de ports » à partir de 20 ports distincts refusés ; règles Suricata nmap | Journal du pare-feu (`ship --format fw`), Suricata | Ticket, puis blocage si l'attaque continue |
| 5 | Sondage et exploration web (httpx, katana, Playwright) | UA d'outil, navigateur sans interface, rafales | Journal d'accès web | Notification et ticket |
| 6 | Découverte de contenu (ffuf) | « Énumération de chemins » : plus de 200 chemins, plus de 60 % d'erreurs | Journal d'accès | Ticket, blocage |
| 7 | Scan de vulnérabilités (nuclei) | UA nuclei, chemins sensibles, en-têtes `X-ARTEX-*` | Journal d'accès, Suricata | Blocage si ARTEX est confirmé |
| 8 | Recherche d'API (swagger, graphql, actuator, .env, .git) | « Chemins sensibles sondés », « Introspection GraphQL » | Journal d'accès | Notification et ticket |

## B. Accès initial par le web

| # | Attaque ARTEX | Détection | Réponse |
|---|---|---|---|
| 9 | Injection SQL (sqlmap) | UA sqlmap et charges SQLi (**nouveau** : `UNION SELECT`, `ORDER BY n--`, `information_schema`) | P2 : blocage et ticket |
| 10 | XSS (dalfox) | UA dalfox et charges XSS | P2 : blocage |
| 11 | Inclusion de fichier local et traversée de chemin | Charge « LFI / traversée » | P2 : blocage |
| 12 | LFI vers exécution de code par php2shell (`session.upload_progress`) | Charge php2shell ; sessions PHP piégées trouvées par `hunt` | P1 : preuves, alerte, isolation à approuver |
| 13 | Injection de commande | Charges d'injection de commande | P2 : blocage |
| 14 | SSTI et JNDI (Log4Shell) | Charges `{{ }}` et `${jndi:` | P2 : blocage |
| 15 | SSRF, y compris vers les métadonnées cloud | **Nouveau** : charge « SSRF / accès aux métadonnées » | P2 : blocage |
| 16 | XXE | **Nouveau** : `<!ENTITY`, `<!DOCTYPE … SYSTEM` | P2 : blocage |
| 17 | Injection NoSQL | **Nouveau** : `[$ne]`, `{"$gt":` | P2 : blocage |
| 18 | IDOR et BOLA (parcours d'identifiants) | **Nouveau** : 30 identifiants différents ou plus sur la même route | P2 : blocage |
| 19 | JWT `alg=none` | **Nouveau**, s'il passe dans l'URL ; sinon il faut les journaux de l'API | P2 : blocage |
| 20 | Introspection et alias GraphQL | **Nouveau** : `__schema`, `IntrospectionQuery` | Notification |
| 21 | Contournement de limite de débit (`X-Forwarded-For` usurpé) | Règle Suricata ; le comportement est suivi par IP réelle | Blocage de l'IP réelle |
| 22 | Fichier téléversé puis exécuté (webshell) | **Nouveau** : `.php` exécuté avec succès dans `/uploads/` ; webshell trouvé par `hunt` | P1 : preuves, isolation à approuver |
| 23 | Exploits connus (Spring4Shell, Shellshock, modèles nuclei) | **Nouveau** pour Spring4Shell et Shellshock ; le reste passe par Suricata | P2 : blocage |

## C. Vol d'identifiants

| # | Attaque ARTEX | Détection | Réponse |
|---|---|---|---|
| 24 | Force brute d'un formulaire web (hydra) | UA hydra ; **nouveau** : 20 POST ou plus sur une page de connexion | Blocage |
| 25 | Force brute SSH et autres services (hydra, ncrack) | **Nouveau** : lecture de `auth.log` (`ship --format auth`), 20 échecs ou plus | Blocage |
| 26 | **Connexion réussie après une force brute** | **Nouveau** : succès après au moins 5 échecs | P1 : preuves, isolation à approuver, changement de mot de passe |
| 27 | Mots de passe par défaut | Même chose que 24 à 26 | Même chose |
| 28 | Cassage hors ligne (hashcat, john) | **Indétectable** : il se fait chez l'attaquant | Hachages forts (argon2, bcrypt), MFA, rotation après incident |

## D. Après l'intrusion

| # | Attaque ARTEX | Détection | Réponse |
|---|---|---|---|
| 29 | Webshell ou exécution de code sur le serveur | `hunt` (sessions piégées, webshells), règles YARA | P1 : isolation à approuver |
| 30 | Mouvement latéral (impacket : psexec, wmiexec, secretsdump, Kerberoast ; SMB, RPC, NFS) | **Nouveau** : alertes IDS reconnues comme mouvement latéral, étape « exécution » | P1 : isolation à approuver |
| 31 | Contournement d'EDR | Hors du périmètre du SOAR : c'est le rôle de ton EDR, qui peut envoyer ses alertes dans `/api/v1/events` | Selon l'alerte |

## E. Infrastructure d'ARTEX

| # | Élément | Détection | Réponse |
|---|---|---|---|
| 32 | Rappels hors bande (OAST, interactsh) | **Nouveau** : si la source est dans `home_networks`, c'est **ton** serveur qui appelle : il est traité comme compromis, sans blocage de ta propre IP | P1 : isolation à approuver |
| 33 | Proxy MITM ou relecture (en-têtes `X-ARTEX-*`) | Signature d'en-tête (Suricata) | Blocage |
| 34 | Instance ARTEX installée chez toi (ports 8787 et 8788, vérification de mise à jour) | `hunt` : processus, ports, fichiers ARTEX | P1 |
| 35 | Furtivité (profil « quiet » à 2 requêtes par seconde, changement d'UA, SOCKS) | Les charges et l'énumération restent visibles même lentement ; « Rotation de User-Agent » | Blocage sur la charge |

## Limites, dites franchement

- **Rotation d'IP** (SOCKS, plusieurs sorties) : chaque nouvelle IP repart de zéro. Les charges
  malveillantes sont bloquées dès la première requête, mais la reconnaissance lente répartie sur
  plusieurs IP peut passer. La défense de fond reste de corriger les vulnérabilités.
- **Trafic HTTPS** : le SOAR lit les journaux du serveur web, donc après déchiffrement. Suricata ne
  voit pas le contenu HTTPS sans terminaison TLS.
- **Charges dans le corps des POST** : les journaux d'accès ne contiennent que l'URL. Pour voir le
  corps, il faut un WAF (ModSecurity) ou Suricata devant un HTTP en clair, puis l'envoi de leurs
  alertes.
- **Ce qui se passe chez l'attaquant** (OSINT passif, cassage hors ligne) est invisible par nature.

## Sources à brancher

| Source | Commande | Couvre |
|---|---|---|
| Journal d'accès nginx ou Apache | `artex-soar ship /var/log/nginx/access.log --target web01` | A5 à A8, B, C24 |
| `auth.log` (SSH) | `artex-soar ship /var/log/auth.log --format auth --target web01` | C25 à C27 |
| Journal du pare-feu (règle LOG) | `artex-soar ship /var/log/kern.log --format fw` | A4 |
| Suricata EVE | `artex-soar ship /var/log/suricata/eve.json --format eve` | A2, A3, B21, D30, E32, E33 |
| Chasse sur le serveur | `artex-soar hunt --host-name web01 --webroot /var/www` | B12, B22, D29, E34 |
