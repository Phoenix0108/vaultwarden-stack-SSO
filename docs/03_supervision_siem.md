# Phase 6 — Hygiène, supervision, points de collecte SIEM

## 1. Purge des artefacts de debug (avant mise en production)

- `SSO_DEBUG_TOKENS` : vérifier qu'il n'apparaît nulle part en dur dans `docker-compose.yml`/`.env` en dehors d'un usage ponctuel commenté (déjà le cas dans les livrables de ce dépôt). Si activé pour un diagnostic, le retirer et **purger les logs concernés** immédiatement après.
- Keytab temporaire (`C:\authentik.keytab` sur le DC, fichier `.b64` lors de l'upload Authentik) : confirmer leur suppression effective (Phase 2/3).
- Captures d'écran, exports de tokens, historiques de commandes contenant des secrets : purge locale sur les postes d'administration ayant servi au déploiement.
- Historique PowerShell (`Get-History`, transcript si activé) sur le DC après exécution de `Setup-KerberosSPNEGO-DC.ps1` : le mot de passe en clair n'y apparaît jamais en tant que variable écrite en log, mais la ligne de commande `ktpass` (incluant `-pass`) peut transiter par l'audit 4688 si la journalisation de ligne de commande est activée — vérifier la rétention de cet événement et restreindre l'accès au journal Sécurité aux seuls administrateurs Tier-0.

## 2. Points de collecte SIEM (nouveaux, cumulatifs avec l'existant)

| Source | Signal | Détection |
|---|---|---|
| DC — Sécurité, événements 4768/4769, filtrés sur `svc-authentik-krb` | Émission/renouvellement de tickets de service | Usage anormal du compte : toute demande où `svc-authentik-krb` apparaît comme **client** (et non comme service cible) est une anomalie — ce compte n'a aucune raison de demander un TGT pour lui-même en usage normal. |
| Authentik — Events | `login` avec `source=kerberos-sso` vs stage password traversé | Un fallback password en provenance d'une IP du `CLIENT_SUBNET` est une anomalie (le SPNEGO aurait dû réussir) ; volume anormal d'échecs SPNEGO (`login_failed`) depuis une même IP = poste hors domaine insistant ou scan. |
| OIDCWarden — logs applicatifs | Device approval, Account Recovery | Toute Account Recovery non planifiée (hors procédure à 4 yeux documentée) = incident à traiter comme une tentative de contournement TDE. |
| Hôte Docker — `VW-EGRESS-DROP` (iptables `DOCKER-USER`) | Paquets droppés sur `authentik_egress` | Compteur ≠ 0 en régime nominal = anomalie (tentative d'egress vers une destination autre qu'Authentik:443) — inchangé dans le principe depuis l'itération AD FS. |
| DC — Sécurité, User Rights Assignment | Application effective de `SeDenyInteractiveLogonRight`/`SeDenyRemoteInteractiveLogonRight` sur `GG-SvcAccounts-DenyInteractiveLogon` | Vérification périodique (pas seulement à l'installation) que la GPO reste liée et appliquée — une désactivation accidentelle de cette GPO réintroduirait un vecteur de logon interactif sur un compte de service. |

## 3. Rotation et cycle de vie des secrets

- **Keytab / compte `svc-authentik-krb`** : classer comme secret sensible (équivalent au mot de passe du compte). Rotation planifiée = régénération complète (nouveau mot de passe + `ktpass` + réimport dans Authentik), pas de rotation partielle. Inventorier dans le coffre d'exploitation : date de génération, kvno courant, empreinte SHA-256 du dernier keytab valide.
- **`SSO_CLIENT_SECRET`** : rotation via le Provider Authentik (regénération du secret) + mise à jour synchronisée du `.env` + `docker compose up -d`. Ne jamais faire l'un sans l'autre (piège déjà rencontré sur l'itération AD FS : secret désynchronisé → `access_denied`).
- **`ADMIN_TOKEN`** : rotation indépendante, régénérer via `openssl rand -base64 48` et mettre à jour `.env`.

## 4. Matrice de déprovisionnement (mise à jour — ajout de la couche Device Key)

Le départ d'un utilisateur ou la compromission d'un compte AD doit déclencher, dans l'ordre :

1. Désactivation du compte AD (coupe immédiatement SPNEGO et, au refresh suivant, le token OIDC).
2. Révocation explicite du/des device(s) dans `/admin` OIDCWarden (la désactivation AD seule ne détruit pas une Device Key déjà déverrouillée localement).
3. Retrait du groupe AD mappé à l'Organization SSO (cohérence avec `SSO_ORGANIZATIONS_REVOCATION` si activé).
4. Wipe/reimage du poste si le device était approuvé et que le contexte (départ pour cause, compromission avérée) le justifie — sinon, au minimum, vérification que le poste repasse par un onboarding TDE propre au prochain utilisateur.
5. Journalisation de chaque étape (SIEM) avec horodatage, pour audit de conformité du déprovisionnement.

## 5. Ce qui reste hors périmètre de ce document

- Le détail des règles de corrélation SIEM (seuils, fenêtres temporelles) dépend du produit SIEM cible — ce document liste les **signaux à collecter**, pas leur implémentation.
- Le MFA Authentik (backlog prioritaire, cf. `02_risk_analysis_tde.md`) introduira de nouveaux événements à superviser une fois arbitré.
