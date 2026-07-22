# Rétrospective — Intégration SSO OIDC Vaultwarden ↔ AD FS

> **Objet** : mémoire du projet. Recense **chaque embûche** rencontrée lors de la première mise en œuvre, sa cause racine, sa résolution, et la leçon à retenir pour le redéploiement propre.
> **Approche** : Security by Design. Chaque point inclut, quand pertinent, l'analyse de risque associée.
> **Contexte lab** : hôte tout-en-un `SRVADTEST` (AD DS + AD CS + AD FS + DNS, Windows Server 2025 / build 26100, AD FS FBL 2019) ; hôte Docker `SRVVAULTWARDENTEST` (Debian 13) ; Vaultwarden 1.36.0 + web-vault 2026.4.1 derrière Caddy.

---

## Résultat final (ce qui fonctionne)

SSO OIDC opérationnel de bout en bout : login `test@vaultwardensso.local` → redirection AD FS → retour → master password → **compte provisionné en JIT** (visible dans `/admin → Users`, statut *Verified*, SSO Identifier AD FS présent).

**La configuration gagnante tient en 4 conditions cumulatives, toutes obligatoires** :
1. Réseau : conteneur → AD FS:443 joignable (DNS + route + firewall) **et** navigateur → AD FS:443 joignable.
2. TLS : conteneur fait confiance à la CA AD CS (id_token discovery en HTTPS).
3. OIDC : issuer à la casse exacte, secret client synchronisé, scopes `openid email profile offline_access`.
4. **Claims AD FS 2016+** : scope **`allatclaims`** accordé au client **+** claim `email` émis **sans** `email_verified` typé chaîne.

---

## Chronologie des embûches (dans l'ordre rencontré)

### 1. Résolution DNS depuis le conteneur — `could not resolve host`
- **Symptôme** : `curl` depuis le conteneur → `Could not resolve host: srvadtest.vaultwardensso.local`.
- **Cause** : le conteneur (réseau Docker `internal`) n'utilise pas le DNS de l'AD ; le résolveur Docker relaie parfois vers un DNS public de secours qui ignore la zone `.local`. Piège additionnel : `.local` = TLD réservé mDNS (RFC 6762).
- **Résolution** : `extra_hosts: ["srvadtest.vaultwardensso.local:192.168.100.93"]` (résolution statique pour la dépendance critique).
- **Risque associé** : un résolveur public de secours **fuite les noms internes** (OPSEC). Ne jamais laisser de fallback public.
- **Leçon** : pour l'IdP (dépendance unique et critique), la résolution statique est la plus sûre et résiliente.

### 2. `internal: true` bloque l'egress vers AD FS — `Connection timed out`
- **Symptôme** : nom résolu, mais `curl` timeout (pas de RST).
- **Cause** : un réseau Docker `internal: true` supprime **tout** forward du bridge (WAN *et* LAN). AD FS est sur le LAN physique → injoignable.
- **Résolution** : réseau dédié `adfs_egress` (bridge NATé, `/29`) en plus du `backend` interne, **bridé** par pare-feu (règles `DOCKER-USER`).
- **Risque associé** : un bridge NATé non filtré rouvrirait tout le LAN/WAN → surface d'attaque. D'où l'allow-list `DOCKER-USER` (default-deny, une seule destination).
- **Leçon** : `internal` est un tout-ou-rien ; la bonne granularité = réseau d'egress dédié + filtrage L4 explicite.

### 3. Le pare-feu Windows d'AD FS bloque le 443 entrant — timeout hôte
- **Symptôme** : ICMP OK, 443 timeout (sans RST), même **depuis l'hôte** Docker.
- **Cause** : profils pare-feu en `DefaultInboundAction = NotConfigured` (= Block implicite), aucune règle Allow 443.
- **Résolution** : règle inbound 443 **scopée** à la source (hôte Docker pour le back-channel, puis subnet client pour le front-channel), profil **Domain**.
- **Risque associé** : ouvrir 443 en `Any` exposerait le tier-0 à tout le réseau. Scope strict = moindre privilège réseau.
- **Leçon** : tester **depuis le bon plan réseau** (hôte vs conteneur) évite de sur-ouvrir à l'aveugle. Un timeout sans RST = filtrage ; un RST = port fermé mais hôte joignable.

### 4. NIC d'AD FS en profil **Public** → règle Domain inerte
- **Symptôme** : règle firewall Domain posée, mais 443 toujours bloqué. `Get-NetConnectionProfile` = `Public`.
- **Cause** : service **NLA (`NlaSvc`) arrêté** + DNS de la carte sur `127.0.0.1` seul → NLA n'a pas pu valider le domaine au boot → catégorie figée en Public → **toutes** les règles Domain inertes.
- **Résolution** : DNS de la NIC sur l'IP réelle du DC en primaire (`192.168.100.93`), `NlaSvc` en `delayed-auto` (`sc.exe config NlaSvc start= delayed-auto`), bounce de la NIC pour re-catégoriser → `DomainAuthenticated`.
- **Risque associé** : une NIC de DC en Public désactive silencieusement le firewall Domain de **tous** les services d'annuaire — anomalie de posture majeure.
- **Leçon** : sur un DC auto-hébergé DNS, NLA doit démarrer **après** AD DS/DNS. `AutomaticDelayedStart` garantit une catégorisation fiable à chaque reboot.

### 5. Règles `DOCKER-USER` non appliquées — `iptables: commande introuvable`
- **Symptôme** : les `iptables -I DOCKER-USER` échouent malgré iptables installé.
- **Cause** : `PATH` shell incomplet (`/usr/sbin` absent).
- **Résolution** : `export PATH="$PATH:/usr/sbin:/sbin" ; hash -r`.
- **Piège persistance** : **ne pas** utiliser `netfilter-persistent` (s'exécute avant Docker au boot → chaîne `DOCKER-USER` inexistante → restauration échoue → fenêtre sans filtrage). Utiliser une **unité systemd** `After=docker.service` avec script idempotent.
- **Leçon** : ordre de démarrage critique pour le filtrage des chaînes Docker.

### 6. Confiance TLS conteneur → AD FS — `unknown CA` / `unable to get local issuer`
- **Symptôme** : TCP OK, handshake TLS échoue à la vérification de chaîne.
- **Cause** : le conteneur ne fait pas confiance à la CA racine AD CS (Caddy en `tls internal`).
- **Résolution** : image dérivée `FROM vaultwarden/server:1.36.0` + `COPY adcs-root.crt` + `RUN update-ca-certificates`. Racine exportée via `Export-Certificate -Type CERT`, convertie DER→PEM, **empreinte SHA-1 vérifiée** après transfert.
- **Risque associé** : ne **jamais** utiliser `--insecure`/`-k` (désactive la validation → MITM sur le flux d'auth). On ajoute la confiance à *sa* CA, on ne supprime pas la vérification.
- **PKI cible** : chaîne mono-niveau (racine auto-signée en ligne) = anti-pattern. Cible = deux niveaux (racine offline + AC émettrice).
- **Leçon** : bonus, l'image dérivée fige aussi la version (`:1.36.0`, fini le `:latest`).

### 7. Casse de l'`issuer` — `unexpected issuer URI`
- **Symptôme** : `Failed to discover OpenID provider: unexpected issuer URI 'https://SRVADTEST...' (expected 'https://srvadtest...')`.
- **Cause** : validation OIDC de l'`iss` **sensible à la casse**. AD FS publie l'issuer avec le HostName tel quel (`SRVADTEST` majuscules) ; le champ Vaultwarden était en minuscules.
- **Résolution** : reporter `Authority Server` **verbatim** depuis le discovery (`https://SRVADTEST.vaultwardensso.local/adfs`).
- **Leçon** : toujours copier l'issuer depuis `/.well-known/openid-configuration`, jamais le retaper.

### 8. Secret client désynchronisé — `MSIS9622 access_denied`
- **Symptôme** : auth utilisateur OK mais échange de code refusé (`échec authentification client`).
- **Cause** : le secret dans le champ Vaultwarden ≠ dernier secret généré côté AD FS.
- **Résolution** : `Set-AdfsServerApplication -ResetClientSecret -PassThru` (ce build ne supporte pas `-GenerateClientSecret` ni `-ClientSecret`), report immédiat de la valeur.
- **Pièges PowerShell rencontrés** : `-GenerateClientSecret` inexistant sur `Set-*` ; `RandomNumberGenerator::Fill()` absent en .NET Framework 4.x (PS 5.1) → tableau de zéros → secret nul `AAAA...` (entropie 0, jamais poussé heureusement).
- **Rotation** : `-ChangeClientSecret` (rotation sans coupure) vs `-ResetClientSecret` (révocation immédiate/incident).

### 9. Politique d'accès AD FS vide — faille de moindre privilège
- **Symptôme** : `AccessControlPolicyName` vide → tout compte AD authentifié obtient un jeton → couplé au JIT + `SSO_ONLY`, **n'importe quel utilisateur du domaine s'auto-crée un coffre**.
- **Cause** : aucune restriction d'accès au niveau IdP.
- **Résolution** : `Set-AdfsWebApiApplication -IssuanceAuthorizationRules` avec règle `Permit … groupsid == <SID grp-vaultwarden>` (portable/auditable, indépendante de la langue). Piège : la politique intégrée `PermitSpecificGroup` a un **nom localisé** (`ADMIN0077` si on passe le nom anglais sur système FR → utiliser `Get-AdfsAccessControlPolicy` ou la règle d'autorisation directe).
- **Leçon** : la barrière IAM doit être portée à l'IdP, **avant** émission du jeton.

### 10. Scope OIDC — distinction back-channel vs client interne
- **Piège** : la requête `POST /identity/connect/token` (client web Bitwarden interne) porte `scope: api offline_access` — **normal**, sans rapport avec AD FS. Ne pas la confondre avec la requête `/adfs/oauth2/authorize` (le vrai scope OIDC vers AD FS).
- **Piège doublon** : Vaultwarden ajoute `openid` automatiquement ; le saisir aussi dans le champ → `scope: openid openid email...` (dédupliqué par AD FS mais à éviter). Ne mettre que `email profile offline_access` dans le champ.

### 11. ⭐ LE blocage final — claim `email` absent de l'id_token (`Neither id token nor userinfo contained an email`)
- **Symptôme** : flux complet, mais Vaultwarden ne trouve pas l'email.
- **Fausses pistes écartées une à une (via audit AD FS event 501)** :
  - Règle `LdapClaims` sur `windowsaccountname` → **claim absent** du pipeline OIDC → règle inerte.
  - Règle sur `primarysid` → **absent** aussi → `MSIS9604` (param LDAP vide).
  - Règle sur `upn` → **absent** aussi → règle inerte.
  - Le **seul** claim d'entrée disponible était `nameidentifier` = **GUID du client applicatif**, pas de l'utilisateur → aucune requête LDAP possible.
- **CAUSE RACINE réelle** (documentée Microsoft) : **AD FS 2016+ n'émet les claims custom dans l'id_token que si le scope `allatclaims` est accordé** au couple client/RP (et/ou `response_mode=form_post`). Sans `allatclaims`, les claims des transform rules ne remontent jamais dans l'id_token, quelle que soit la règle.
- **Résolution** :
  1. `Set-AdfsApplicationPermission -TargetIdentifier <perm> -AddScope 'allatclaims'` (piège : `Grant-AdfsApplicationPermission` échoue en `MSIS7626` car la permission existe déjà → utiliser `Set-… -AddScope`).
  2. Règle d'émission `email` depuis l'attribut `mail`.
- **Sources** : Microsoft Learn « Customize claims to be emitted in id_token when using OpenID Connect or OAuth with AD FS 2016 or later » ; corroboré par l'issue GitHub grafana/grafana #40656 (claims custom non émis si `response_mode ≠ form_post`).

### 12. Typage `email_verified` — `invalid type: string "true", expected a boolean`
- **Symptôme** : id_token reçu **avec** l'email, mais parsing JSON refusé.
- **Cause** : AD FS sérialise le claim `email_verified` en **chaîne** `"true"` malgré `ValueType=boolean` ; Vaultwarden attend un **booléen JSON**.
- **Résolution retenue** : **ne pas émettre** `email_verified` et couvrir l'absence par `SSO_ALLOW_UNKNOWN_EMAIL_VERIFICATION=true`.
- **Analyse de risque** : ce flag accepte un email non « vérifié ». Risque neutralisé en défense en profondeur par : (a) `Allow email association` décochée, (b) politique d'accès `Permit grp-vaultwarden`, (c) email issu de l'attribut `mail` **de l'annuaire** (source de confiance, non saisi par l'utilisateur).

---

## Pièges transverses (à mémoriser)

| Piège | Détail | Parade |
|---|---|---|
| **Encodage PowerShell** | `.ps1` UTF-8 sans BOM lu en ANSI par PS 5.1 → tiret cadratin `—` corrompu → parseur cassé | Scripts **100 % ASCII** ou UTF-8 **with BOM** |
| **Continuation backtick** | backtick suivi d'un espace/commentaire casse la ligne | **splatting** (`@{}`) au lieu de backticks |
| **Noms localisés (FR)** | politiques d'accès, sous-catégories audit ont des libellés FR | GUID (`{0CCE9222-...}`) ou `Get-*` pour le nom exact |
| **`Rename-NetFirewallRule`** | change `Name`, pas `DisplayName` | `Set-NetFirewallRule -NewDisplayName` |
| **Tester du bon plan** | hôte ≠ conteneur ≠ navigateur (3 chemins réseau) | reproduire le chemin réel du trafic |
| **Placeholder non substitué** | `CHAINE_BASE64_COLLEE`, `<NOM_EXACT>` laissés littéraux | toujours remplacer avant exécution |
| **`Get-WinEvent` debug logs** | journaux analytiques → `-Oldest` obligatoire | `-Oldest` ou activer via `wevtutil sl … /e:true` |

---

## Dette de sécurité identifiée (à corriger au redéploiement)

1. **SPOF tier-0** : DC + AC + AD FS colocalisés → compromission = forêt entière. Cible : rôles séparés + WAP en DMZ pour AD FS.
2. **PKI mono-niveau** : racine en ligne colocalisée. Cible : racine offline + AC émettrice.
3. **`tls internal` Caddy** : remplacer par certificat serveur issu de l'AC interne (chaîne approuvée jusqu'au navigateur).
4. **Secret en clair dans `config.json`** : migrer vers `SSO_CLIENT_SECRET_FILE` + secret Docker.
5. **Firewall en `PolicyStoreSource: Local`** : porter en **GPO** (résilience au rebuild, auditabilité).
6. **Débogage** : `SSO_DEBUG_TOKENS` / `Log all tokens` laissés actifs trop longtemps (jetons en clair sur disque) → procédure d'hygiène stricte (cf. runbook).

---

## Ordre de résolution optimal (pour le redéploiement)

Le redéploiement doit suivre l'ordre des **couches**, chaque étape validée avant la suivante (une modif = une mesure) :

```
1. AD : DNS NIC + NLA (DomainAuthenticated) + groupe + attribut mail
2. AD CS : export racine + empreinte
3. AD FS : app group + secret + politique accès + allatclaims + règle email
4. Réseau AD FS : firewall inbound 443 scopé (Domain)
5. Docker : réseaux backend(internal)+adfs_egress + DOCKER-USER + systemd
6. TLS : image dérivée avec racine AD CS + épinglage version
7. Vaultwarden : config SSO (/admin ou env), issuer casse exacte
8. Validation : curl hôte -> curl conteneur -> login test -> JIT
9. Hygiène : retrait debug, purge logs, durcissement final
```
