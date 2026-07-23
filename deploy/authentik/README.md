# Phase 3 — Authentik : source LDAP (provisioning) + source Kerberos (SPNEGO auto-login)

## Pré-requis

- Phase 0 terminée : `deploy/environment.env` rempli (realm, DC, hostnames, réseaux clients...).
- Phase 2 terminée : keytab `authentik.keytab` transféré sur l'hôte Docker, intégrité SHA-256 vérifiée des deux côtés, `chown root:root` / `chmod 600`.
- **Source LDAP configurée (voir 0. ci-dessous) — c'est elle qui reste l'unique point de provisioning des comptes.** La source Kerberos décrite dans ce document ne provisionne jamais de compte (`sync_users: false`), elle ne fait que valider un ticket déjà émis pour un compte que la source LDAP a déjà créé.

## 0. Source LDAP (provisioning des comptes — prérequis réel)

Cette source n'existe pas par défaut sur un domaine reparti de zéro : elle doit être créée.

1. **DC** : provisionner le compte de bind dédié (jamais `Administrator`, jamais le compte SPNEGO) :
   ```powershell
   . .\deploy\Set-Environment.ps1
   cd deploy\kerberos
   .\Setup-LDAPBind-DC.ps1
   ```
   Crée (idempotent) l'OU `LDAP_SYNC_OU_NAME` (défaut `Vaultwarden` — périmètre de recherche — à peupler séparément avec les vrais comptes à synchroniser si ce n'est pas déjà fait), le compte de bind (défaut `svc-authentik-ldap`, lecture seule, aucune délégation, membre du groupe deny-interactive-logon), et écrit le mot de passe dans `C:\authentik-ldap-bind.txt` (ACL restreinte, jamais affiché en console).
2. **Transfert** (même discipline que le keytab, jamais retapé à la main) :
   ```bash
   smbclient "//$DC_IP/C\$" -U "${DOMAIN_NETBIOS}\\Administrator" -c 'get authentik-ldap-bind.txt'
   ```
3. **Authentik (GUI)** : Directory → Federation & Social login → Create → **LDAP Source**.
   - Server URI : `ldaps://<DC_IP>:636` (jamais `ldap://` en clair pour un bind avec mot de passe, jamais "disable full TLS validation" — vérifier d'abord `openssl s_client -connect <DC_IP>:636 -CAfile deploy/docker/adcs-root.crt` depuis l'hôte Docker → `Verify return code: 0`).
   - Bind CN : le Bind DN affiché par le script.
   - Bind Password : contenu de `authentik-ldap-bind.txt`.
   - Base DN : `OU=<LDAP_SYNC_OU_NAME>,<DN de votre domaine>` (le périmètre créé à l'étape 1).
   - User Property Mappings / Group Property Mappings : mappings par défaut Authentik (`goauthentik.io/sources/ldap/*`) suffisent pour un premier test.
4. **Purge** : supprimer `authentik-ldap-bind.txt` du DC et sa copie transitoire côté hôte Docker une fois la source validée (bouton "Sync" dans l'UI Authentik → pas d'erreur, comptes visibles dans Directory → Users).

## 1. Rendu et import du blueprint (source Kerberos SPNEGO)

`kerberos-sso-blueprint.yaml` est un **template** (pas un fichier à importer tel quel) : il couvre la création de la source Kerberos, la policy de redirection (multi-réseaux), un **Redirect Stage** dédié (URL statique vers la source Kerberos) et son binding sur le flow d'authentification par défaut, avant le stage d'identification — **sauf le keytab** (secret binaire, jamais dans un fichier versionné).

Mécanique (vérifiée directement dans le code source Authentik, après plusieurs échecs par simple lecture de doc) : il n'existe **pas** de fonction permettant à une Expression Policy de renvoyer une URL de redirection — une policy ne renvoie qu'un booléen. La redirection réelle passe donc par un Redirect Stage inséré *avant* le stage d'identification (order plus bas) ; la policy IP sert de gate sur ce Redirect Stage : hors de tous les `CLIENT_SUBNETS`, le stage est simplement sauté et le flow continue normalement vers l'identification/formulaire password.

1. Rendre le template : `./deploy/authentik/render-blueprint.sh` (lit `deploy/environment.env` : `REALM`, `DC_IP`, `DOMAIN_DNS`, `CLIENT_SUBNETS` — cette dernière accepte une liste de CIDR séparés par des virgules, un par réseau/VLAN client autorisé) → produit `kerberos-sso-blueprint.rendered.yaml` (jamais versionné).
2. Vérifier le slug réel du flow d'authentification par défaut sur votre instance (Admin → Flows → celui marqué *default-authentication-flow*) et l'`order` de son stage d'identification (généralement `10`) — le blueprint insère le Redirect Stage à `order: 5` ; ajuster si votre installation diffère.
3. Importer le fichier **rendu** (pas le template) : Admin → System → Blueprints → Import, ou `docker exec -i authentik-server ak import_blueprint < deploy/authentik/kerberos-sso-blueprint.rendered.yaml`.
4. **Upload manuel du keytab** (jamais transité par un service tiers) :
   ```
   base64 -w0 authentik.keytab > authentik.keytab.b64
   ```
   Coller le contenu de `authentik.keytab.b64` dans Directory → Federation & Social login → *Kerberos SPNEGO SSO* → champ Keytab. Supprimer le fichier `.b64` local immédiatement après (`shred -u` ou équivalent).
5. Vérifier dans la source Kerberos créée :
   - `spnego_server_name` **vide** (volontaire — voir commentaire dans le blueprint : renseigner ce champ fait échouer systématiquement l'acquisition des credentials dans cet environnement, bug/limitation de cette fonctionnalité encore en préversion ; laisser vide fait fonctionner l'auto-détection depuis le keytab, sans ambiguïté puisqu'il n'y a qu'une seule entrée)
   - `user_matching_mode = username_link` (**pas** `username_deny` — contrairement à l'intuition, "deny" signifie ici *refuse de relier* à un compte existant, l'inverse de ce que ce projet veut ; `username_link` relie au compte déjà provisionné par la source LDAP sans jamais en créer un nouveau, garantie déjà assurée indépendamment par `sync_users = false`)
   - `sync_users = false` (le provisioning reste le monopole de la source LDAP)
   - `authentication_flow = default-source-authentication` (sinon `Bad Request: Le flux configuré n'existe pas` après un SPNEGO pourtant accepté)

## 2. Ne pas supprimer le stage password

Le flow d'authentification par défaut garde son stage password (break-glass : poste hors domaine, mobile, échec SPNEGO). Seul le Redirect Stage (gaté par la policy `redirect-kerberos-if-intranet`) tente le SPNEGO en priorité pour les clients d'un des `CLIENT_SUBNETS` ; hors de tous ces réseaux, la policy retourne `False`, le Redirect Stage est sauté et le flow continue normalement vers le formulaire.

## 3. Durcissement session (à vérifier manuellement, hors blueprint)

- Durée de session Authentik : aligner sur la politique de verrouillage Windows, ≤ 8 h glissantes (Admin → Flows & Stages → *user-authentication* stage, ou au niveau de l'Application/Provider selon la version).
- Cookies `Secure` + `HttpOnly` : comportement par défaut Authentik derrière TLS — vérifier que rien ne le désactive en amont (reverse proxy, `AUTHENTIK_COOKIE_DOMAIN`).
- Pas de "remember me" long sur ce flow.

## 4. Gates séquentiels (à exécuter dans l'ordre, un gate = un STOP si échec)

**a. Poste du domaine, session ouverte — negotiate direct sur l'endpoint source :**
```
curl --negotiate -u : https://<AUTH_HOSTNAME>/source/kerberos/kerberos-sso/
```
Attendu : `302` (redirection vers le flow, PAS un `401` final).

**b. Navigateur, poste du domaine (dans un des `CLIENT_SUBNETS`) — parcours complet :**
Accéder à `https://<VAULT_HOSTNAME>` → redirection Authentik → **aucun formulaire affiché** → retour Vaultwarden authentifié.

**c. Poste HORS de tous les `CLIENT_SUBNETS` (ou hors domaine) :**
Le formulaire mot de passe Authentik s'affiche (fallback fonctionnel — confirme que le stage password n'a pas été supprimé et que la policy ne bloque pas hors périmètre).

**d. Logs Authentik :**
Admin → Events → un événement `login` portant la source `kerberos-sso`, **sans** trace de traversée du stage password pour ce même login.

**e. Accès admin direct, depuis un réseau client :**
Depuis un poste d'un des `CLIENT_SUBNETS`, accéder à `https://<AUTH_HOSTNAME>/if/admin/` et se connecter avec `akadmin` (ou tout compte local Authentik) → le formulaire email/mot de passe standard doit s'afficher, **sans redirection Kerberos**. Ce gate existe suite à un incident réel : la policy de redirection est bindée sur `default-authentication-flow`, partagé par tous les logins Authentik — sans le filtre `client_id` (présent uniquement lors d'une connexion pilotée par une application OAuth2 comme Vaultwarden), un admin sur le LAN se faisait rediriger comme n'importe quel utilisateur Vaultwarden, avec échec puisque `akadmin` n'est pas un compte AD → verrouillage total de l'admin.

**f. Multi-réseaux (si `CLIENT_SUBNETS` liste plusieurs CIDR) :**
Répéter les gates (a)/(b) depuis **chacun** des réseaux listés (LAN filaire, WiFi corporate, VPN...) — un seul rendu du blueprint les couvre tous, mais chaque réseau reste à valider séparément (routage, X-Forwarded-For correctement transmis jusqu'à Caddy pour ce segment).

## Supervision (à consigner dans le SIEM, Phase 6)

- SPNEGO exposé uniquement sur les périmètres listés dans `CLIENT_SUBNETS` : le firewall inbound du flux client → Authentik reste scopé à ces réseaux (vérifier au niveau réseau, hors Authentik).
- Échecs SPNEGO répétés (poste hors domaine insistant, scan) → alerter sur un volume anormal d'événements `login_failed` avec `source=kerberos-sso` depuis une même IP.
- Un login Kerberos réussi pour un compte désactivé côté AD est impossible par construction (pas de TGT émis) — pas de détection dédiée nécessaire côté Authentik pour ce cas.
