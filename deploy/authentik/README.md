# Phase 3 — Authentik : source Kerberos + flow SPNEGO auto-login

## Pré-requis

- Phase 2 terminée : keytab `authentik.keytab` transféré sur le Debian (`192.168.100.89`), intégrité SHA-256 vérifiée des deux côtés, `chown root:root` / `chmod 600`.
- Une source LDAP existante (scope `OU=Vaultwarden`) qui reste l'unique point de provisioning des comptes — **cette phase n'en crée pas d'autre.**

## 1. Import du blueprint

`kerberos-sso-blueprint.yaml` couvre la création de la source Kerberos, la policy de redirection et son binding sur le stage d'identification — **sauf le keytab** (secret binaire, jamais dans un fichier versionné).

1. Substituer `<CLIENT_SUBNET>` dans le blueprint par le CIDR réel du LAN intranet (ex. `192.168.100.0/24`) avant import.
2. Vérifier le slug réel du flow d'authentification par défaut sur votre instance (Admin → Flows → celui marqué *default-authentication-flow*, et son stage d'identification) — remplacer les valeurs `default-authentication-flow` / `default-authentication-identification` dans le blueprint si votre installation utilise des noms différents (le nom exact peut varier selon la version/l'historique de l'instance).
3. Importer : Admin → System → Blueprints → Import, ou `ak import_blueprint deploy/authentik/kerberos-sso-blueprint.yaml` depuis le conteneur/hôte Authentik.
4. **Upload manuel du keytab** (jamais transité par un service tiers) :
   ```
   base64 -w0 /chemin/authentik.keytab > authentik.keytab.b64
   ```
   Coller le contenu de `authentik.keytab.b64` dans Directory → Federation & Social login → *Kerberos SPNEGO SSO* → champ Keytab. Supprimer le fichier `.b64` local immédiatement après (`shred -u` ou équivalent).
5. Vérifier dans la source Kerberos créée :
   - `spnego_server_name = HTTP/auth.vaultwardensso.local`
   - `user_matching_mode = username_deny` (**pas** `username_link` — deny = aucune création d'utilisateur si le principal ne correspond à aucun compte provisionné par la source LDAP)
   - `sync_users = false` (le provisioning reste le monopole de la source LDAP `OU=Vaultwarden`)

## 2. Ne pas supprimer le stage password

Le flow d'authentification par défaut garde son stage password (break-glass : poste hors domaine, mobile, échec SPNEGO). Seule la policy de redirection (`redirect-kerberos-if-intranet`) tente le SPNEGO en priorité pour les clients du `CLIENT_SUBNET` ; hors de ce subnet, la policy retourne `True` et le flow continue normalement vers le formulaire.

## 3. Durcissement session (à vérifier manuellement, hors blueprint)

- Durée de session Authentik : aligner sur la politique de verrouillage Windows, ≤ 8 h glissantes (Admin → Flows & Stages → *user-authentication* stage, ou au niveau de l'Application/Provider selon la version).
- Cookies `Secure` + `HttpOnly` : comportement par défaut Authentik derrière TLS — vérifier que rien ne le désactive en amont (reverse proxy, `AUTHENTIK_COOKIE_DOMAIN`).
- Pas de "remember me" long sur ce flow.

## 4. Gates séquentiels (à exécuter dans l'ordre, un gate = un STOP si échec)

**a. Poste du domaine, session ouverte — negotiate direct sur l'endpoint source :**
```
curl --negotiate -u : https://auth.vaultwardensso.local/source/kerberos/kerberos-sso/login/
```
Attendu : `302` (redirection vers le flow, PAS un `401` final).

**b. Navigateur, poste du domaine — parcours complet :**
Accéder à `https://vault.vaultwardensso.local` → redirection Authentik → **aucun formulaire affiché** → retour Vaultwarden authentifié.

**c. Poste HORS domaine :**
Le formulaire mot de passe Authentik s'affiche (fallback fonctionnel — confirme que le stage password n'a pas été supprimé et que la policy ne bloque pas hors `CLIENT_SUBNET`).

**d. Logs Authentik :**
Admin → Events → un événement `login` portant la source `kerberos-sso`, **sans** trace de traversée du stage password pour ce même login.

## Supervision (à consigner dans le SIEM, Phase 6)

- SPNEGO exposé uniquement sur le périmètre intranet : le firewall inbound du flux client → Authentik reste scopé `CLIENT_SUBNET` (vérifier au niveau réseau, hors Authentik).
- Échecs SPNEGO répétés (poste hors domaine insistant, scan) → alerter sur un volume anormal d'événements `login_failed` avec `source=kerberos-sso` depuis une même IP.
- Un login Kerberos réussi pour un compte désactivé côté AD est impossible par construction (pas de TGT émis) — pas de détection dédiée nécessaire côté Authentik pour ce cas.
