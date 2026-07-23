# Projet — SSO Kerberos passwordless de bout en bout (Vaultwarden/OIDCWarden ↔ Authentik ↔ AD)

Livrables pour un SSO passwordless intranet : ouverture de session Windows (Kerberos SPNEGO) → Authentik (IdP OIDC) → OIDCWarden (fork Vaultwarden, Trusted Device Encryption), sans ressaisie du mot de passe AD ni, après onboarding, du master password.

**Réutilisable sur votre propre infrastructure** : aucune valeur (realm, hostnames, IP du DC, réseaux clients) n'est figée dans le code — tout se configure une seule fois dans `deploy/environment.env`. Plusieurs réseaux/VLAN clients (LAN filaire, WiFi corporate, VPN site-to-site, autre site AD...) sont supportés nativement pour la redirection Kerberos automatique.

> **Historique** : ce projet succède à une itération AD FS abandonnée. Voir `legacy/` (conservé pour mémoire — rétrospective et pièges rencontrés — mais **non maintenu et non réutilisable tel quel**).

## Démarrage rapide

1. Copier `deploy/environment.env.example` vers `deploy/environment.env` et renseigner **vos** valeurs (realm AD, DC, hostnames, réseaux clients...) — voir les commentaires du fichier.
2. Suivre `runbook/RUNBOOK_installation.md`, phase par phase (Phase 0 = charger cette config des deux côtés, DC et hôte Docker). Chaque phase a un **gate** : ne pas passer à la suivante tant que le gate n'est pas vert.

| Élément (exemple — remplacer par le vôtre dans `deploy/environment.env`) | Valeur d'exemple |
|---|---|
| DC (AD DS + AD CS + DNS) | Windows Server 2016+, IP interne (`DC_IP`) |
| Hôte Docker | Debian/Ubuntu, non joint au domaine |
| IdP OIDC | Authentik (`AUTH_HOSTNAME`), même VM/hôte Docker que Vaultwarden et Caddy, même `docker-compose.yml` |
| SP | OIDCWarden (fork Vaultwarden avec Trusted Device Encryption) |
| CA | Autorité de certification interne (AD CS Enterprise ou équivalent), thumbprint dans `CA_ROOT_THUMBPRINT` |

## Contenu

```
deploy/
├── environment.env.example           # CONFIG CENTRALE : realm, hostnames, IP DC, reseaux clients (VLAN)... a copier en environment.env
├── Set-Environment.ps1               # charge environment.env dans la session PowerShell (DC) -- dot-source obligatoire
├── caddy/
│   ├── Caddyfile                     # reverse proxy TLS unique pour VAULT_HOSTNAME ET AUTH_HOSTNAME ({$VAR} -- "tout passe par Caddy")
│   └── certs/                        # vault.crt + vault.key (non versionnés, voir .gitignore)
├── docker/
│   ├── docker-compose.yml            # stack durcie : Caddy + OIDCWarden + Authentik (server/worker/PostgreSQL/Redis) — même VM, même compose
│   ├── Dockerfile                    # image dérivée : embarque la CA interne, version OIDCWarden épinglée
│   └── .env.example                  # secrets + hostnames (à copier en .env, chmod 600)
├── tls/
│   ├── New-VaultCertDC.ps1           # génère + exporte le certificat + la racine CA (Phase 1, DC)
│   └── install-vault-cert.sh         # transfert, conversion, installation, déploiement + gates (Phase 1, hôte Docker)
├── kerberos/
│   ├── Setup-KerberosSPNEGO-DC.ps1   # compte de service + SPN + keytab (Phase 2, à exécuter sur le DC)
│   └── Setup-LDAPBind-DC.ps1         # compte de bind LDAP + OU cible (Phase 2bis, provisioning, à exécuter sur le DC)
├── authentik/
│   ├── kerberos-sso-blueprint.yaml   # TEMPLATE : Source Kerberos + policy de redirection multi-VLAN (Phase 3)
│   ├── render-blueprint.sh           # substitue les placeholders depuis environment.env -> kerberos-sso-blueprint.rendered.yaml
│   └── README.md                     # Source LDAP (§0) + étapes manuelles Kerberos (upload keytab) + gates
└── gpo/
    ├── Deploy-KerberosSSO-GPO.ps1    # GPO navigateurs + pré-provisioning Bitwarden + Firefox policies (Phase 4)
    ├── Set-BitwardenClientPolicy.ps1 # variante manuelle poste par poste (remplace un ancien .reg statique)
    └── firefox-policies.json.example # illustration -- le vrai fichier est généré par Deploy-KerberosSSO-GPO.ps1

docs/
├── 01_architecture.md                # flux, séquence d'authentification, plans réseau
├── 02_risk_analysis_tde.md           # analyse de risque Trusted Device Encryption (Phase 5)
└── 03_supervision_siem.md            # points de collecte SIEM, hygiène, déprovisionnement (Phase 6)

runbook/
└── RUNBOOK_installation.md           # doc de test/install end-to-end, phase par phase, gates et commandes
```

## Ordre de déploiement (une couche = une validation)

| Phase | Étape | Fichier / commande | Gate |
|---|---|---|---|
| 0 | Configuration centrale | `deploy/environment.env` (copie de `.example`), `. .\deploy\Set-Environment.ps1` côté DC | Variables chargées (`$env:REALM`, `$env:DC_IP`, ...), pas de placeholder restant |
| 1 | TLS Caddy (chaîne CA interne) | `deploy/caddy/Caddyfile`, `deploy/docker/docker-compose.yml`, `install-vault-cert.sh` | `openssl s_client` → issuer CA interne, `Verify return code: 0` ; `docker exec vaultwarden curl -fsS https://.../alive` |
| 2 | Compte de service + SPN + keytab (DC) | `deploy/kerberos/Setup-KerberosSPNEGO-DC.ps1` | Script auto-vérifié (anti-doublon SPN, msDS-SupportedEncryptionTypes=24, kvno, SHA-256 keytab) ; validation réelle en Phase 3 |
| 2bis | Source LDAP (provisioning des comptes) | `deploy/kerberos/Setup-LDAPBind-DC.ps1` + config manuelle Authentik | Sync LDAP sans erreur, comptes visibles dans Directory → Users |
| 3 | Kerberos Source Authentik + flow SPNEGO | `deploy/authentik/render-blueprint.sh` + `README.md` | Poste domaine (dans un des `CLIENT_SUBNETS`) → aucun formulaire ; hors subnet → fallback password |
| 4 | GPO postes clients (négociation Kerberos navigateurs) | `deploy/gpo/Deploy-KerberosSSO-GPO.ps1` | `gpresult /r` + header `Authorization: Negotiate` |
| 5 | Bascule OIDCWarden + TDE | `deploy/docker/*` mis à jour, `docs/02_risk_analysis_tde.md` | Login SSO complet, device approval, master password non redemandé |
| 6 | Hygiène, supervision, runbook final | `docs/03_supervision_siem.md` | Purge debug, SIEM, matrice de déprovisionnement |

**Les 7 phases (0 à 6) sont livrées et conçues pour être réutilisées sur n'importe quelle infrastructure AD.** Chaque gate reste à valider par vous sur votre environnement. Voir `runbook/RUNBOOK_installation.md` pour le parcours consolidé, phase par phase.

## Points de sécurité clés (rappel)

- **PKI/TLS** : confiance ajoutée à la CA interne (jamais `--insecure`/`tls internal` en cible), version d'image épinglée.
- **IAM (Phase 2)** : compte de service Kerberos moindre privilège — `Domain Users` seul, `AccountNotDelegated`, AES only (jamais RC4/DES), refus de logon interactif porté par GPO sur un groupe dédié.
- **IAM (Phase 3)** : provisioning des comptes = monopole de la source LDAP ; la source Kerberos est en `user_matching_mode=username_link` (relie au compte LDAP existant par username) avec `sync_users=false`, qui à lui seul garantit qu'elle ne crée jamais de compte.
- **Secrets** : mot de passe du compte de service et keytab jamais affichés/loggés ; keytab traité comme un secret sensible (équivalent au mot de passe du compte), transfert exclusivement via `smbclient` (jamais RDP clipboard), intégrité vérifiée par SHA-256 des deux côtés, suppression du DC après transfert.
- **Moindre privilège navigateurs (Phase 4)** : allowlist stricte à un seul FQDN (jamais de wildcard `*.local`), `AuthNegotiateDelegateAllowlist` volontairement non configuré (pas de délégation Kerberos).
- **Multi-réseaux (`CLIENT_SUBNETS`)** : la policy de redirection Kerberos accepte une liste de CIDR ; hors de toutes ces plages, repli automatique et non bloquant vers le formulaire mot de passe — jamais d'erreur pour un réseau non listé.
- **TDE (Phase 5)** : master password saisi une seule fois par device ; compensations obligatoires (BitLocker, verrouillage de session, break-glass hors organization SSO) détaillées dans `docs/02_risk_analysis_tde.md`. MFA Authentik identifié comme dette prioritaire — le SPNEGO ne doit pas devenir un contournement.
- **Encodage** : scripts PowerShell 100 % ASCII, splatting (pas de backticks de continuation) — leçons de la rétrospective AD FS (`legacy/docs/00_RETROSPECTIVE_embuches.md`).

## Dette de sécurité à traiter (cible production)

1. CDP LDAP-only sur la chaîne AD CS → ajouter un CDP HTTP avant prod (sinon la vérification de révocation échoue hors domaine).
2. SPOF tier-0 (DC/AC colocalisés) — hérité de l'itération précédente, toujours d'actualité.
3. PKI mono-niveau (racine en ligne) — cible : racine offline + AC émettrice.
4. MFA côté Authentik : le SPNEGO ne doit pas devenir un contournement du MFA prévu (arbitrage à faire, cf. brief Phase 5).
5. Réseau `authentik_ldap_egress` (Phase 2bis, Source LDAP) : réseau Docker non-`internal` par nécessité (authentik-server/worker doivent joindre le DC en LDAPS 636 sur le LAN), mais Docker ne permet pas nativement de restreindre un réseau bridge à une IP/port précis — sans filtrage host (`DOCKER-USER`/iptables scopé à `DC_IP:636`), ce réseau autorise en théorie tout egress LAN/WAN depuis authentik-server/worker. À durcir avant prod.

Voir `legacy/docs/00_RETROSPECTIVE_embuches.md` pour l'historique des pièges déjà rencontrés (DNS, egress Docker, NLA, CA, casse issuer, etc.) — plusieurs restent pertinents dans la nouvelle architecture.
