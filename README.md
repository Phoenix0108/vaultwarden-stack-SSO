# Projet — SSO Kerberos passwordless de bout en bout (Vaultwarden/OIDCWarden ↔ Authentik ↔ AD)

Livrables pour un SSO passwordless intranet : ouverture de session Windows (Kerberos SPNEGO) → Authentik (IdP OIDC) → OIDCWarden (fork Vaultwarden, Trusted Device Encryption), sans ressaisie du mot de passe AD ni, après onboarding, du master password.

> **Historique** : ce projet succède à une itération AD FS abandonnée. Voir `legacy/` (conservé pour mémoire — rétrospective et pièges rencontrés — mais **non maintenu et non réutilisable tel quel**).

## Contexte figé

| Élément | Valeur |
|---|---|
| DC (AD DS + AD CS + DNS) | Windows Server 2016, `192.168.100.76` |
| Hôte Docker | Debian 13, `192.168.100.89` |
| IdP OIDC | Authentik, `auth.vaultwardensso.local` |
| SP | Vaultwarden 1.36.0 → bascule prévue OIDCWarden (Phase 5) |
| CA | AD CS Enterprise Root, thumbprint `473BAAC9189D52715E3E73CED9BEC691293BED10` |

## Contenu

```
deploy/
├── caddy/
│   ├── Caddyfile                     # reverse proxy TLS, chaîne AD CS (Phase 1)
│   └── certs/                        # vault.crt + vault.key (non versionnés, voir .gitignore)
├── docker/
│   ├── docker-compose.yml            # stack durcie : Caddy + OIDCWarden (Phases 1 et 5)
│   ├── Dockerfile                    # image dérivée : embarque la CA AD CS, version OIDCWarden épinglée
│   └── .env.example                  # secrets (à copier en .env, chmod 600)
├── tls/
│   ├── New-VaultCertDC.ps1           # génère + exporte le certificat vault.* + la racine AD CS (Phase 1, DC)
│   └── install-vault-cert.sh         # transfert, conversion, installation, déploiement + gates (Phase 1, Debian)
├── kerberos/
│   └── Setup-KerberosSPNEGO-DC.ps1   # compte de service + SPN + keytab (Phase 2, à exécuter sur le DC)
├── authentik/
│   ├── kerberos-sso-blueprint.yaml   # Source Kerberos + policy de redirection (Phase 3)
│   └── README.md                     # étapes manuelles (upload keytab) + gates
├── gpo/
│   ├── Deploy-KerberosSSO-GPO.ps1    # GPO navigateurs + pré-provisioning Bitwarden (Phase 4)
│   ├── firefox-policies.json         # network.negotiate-auth.trusted-uris
│   └── Deploy-BitwardenClients.reg   # variante manuelle poste par poste
├── firewall/
│   └── vw-egress-fw.sh               # allow-list egress DOCKER-USER vers Authentik (Phase 5)
└── systemd/
    └── vw-egress-fw.service          # persistance After=docker.service

docs/
├── 01_architecture.md                # flux, séquence d'authentification, plans réseau
├── 02_risk_analysis_tde.md           # analyse de risque Trusted Device Encryption (Phase 5)
└── 03_supervision_siem.md            # points de collecte SIEM, hygiène, déprovisionnement (Phase 6)

runbook/
└── RUNBOOK_evaluation.md             # doc de test end-to-end, phase par phase, gates et commandes
```

## Ordre de déploiement (une couche = une validation)

| Phase | Étape | Fichier / commande | Gate |
|---|---|---|---|
| 1 | TLS Caddy (chaîne AD CS) | `deploy/caddy/Caddyfile`, `deploy/docker/docker-compose.yml`, `docker compose up -d caddy` | `openssl s_client` → issuer AD CS, `Verify return code: 0` ; `docker exec vaultwarden curl -fsS https://vault.../alive` |
| 2 | Compte de service + SPN + keytab (DC) | `deploy/kerberos/Setup-KerberosSPNEGO-DC.ps1` | Script auto-vérifié (anti-doublon SPN, msDS-SupportedEncryptionTypes=24, kvno, SHA-256 keytab) ; validation réelle en Phase 3 |
| 3 | Kerberos Source Authentik + flow SPNEGO | `deploy/authentik/kerberos-sso-blueprint.yaml` + `README.md` | Poste domaine → aucun formulaire ; poste hors domaine → fallback password |
| 4 | GPO postes clients (négociation Kerberos navigateurs) | `deploy/gpo/Deploy-KerberosSSO-GPO.ps1` | `gpresult /r` + header `Authorization: Negotiate` |
| 5 | Bascule OIDCWarden + TDE | `deploy/docker/*` mis à jour, `docs/02_risk_analysis_tde.md` | Login SSO complet, device approval, master password non redemandé |
| 6 | Hygiène, supervision, runbook final | `docs/03_supervision_siem.md` | Purge debug, SIEM, matrice de déprovisionnement |

**Les 6 phases sont livrées.** Aucune n'a été exécutée contre l'infrastructure réelle (pas d'accès réseau à `192.168.100.0/24` depuis l'environnement d'édition) : chaque gate reste à valider par vous. Voir `runbook/RUNBOOK_evaluation.md` pour le parcours de test consolidé, phase par phase, avec les placeholders à substituer avant exécution.

## Points de sécurité clés (rappel)

- **PKI/TLS** : confiance ajoutée à la CA interne (jamais `--insecure`/`tls internal` en cible), version d'image épinglée.
- **IAM (Phase 2)** : compte de service Kerberos moindre privilège — `Domain Users` seul, `AccountNotDelegated`, AES only (jamais RC4/DES), refus de logon interactif porté par GPO sur un groupe dédié.
- **IAM (Phase 3)** : provisioning des comptes = monopole de la source LDAP (`OU=Vaultwarden`) ; la source Kerberos est en `user_matching_mode=username_deny` et ne crée jamais de compte.
- **Secrets** : mot de passe du compte de service et keytab jamais affichés/loggés ; keytab traité comme un secret sensible (équivalent au mot de passe du compte), transfert exclusivement via `smbclient` (jamais RDP clipboard), intégrité vérifiée par SHA-256 des deux côtés, suppression du DC après transfert.
- **Moindre privilège navigateurs (Phase 4)** : allowlist stricte à un seul FQDN (jamais de wildcard `*.local`), `AuthNegotiateDelegateAllowlist` volontairement non configuré (pas de délégation Kerberos).
- **TDE (Phase 5)** : master password saisi une seule fois par device ; compensations obligatoires (BitLocker, verrouillage de session, break-glass hors organization SSO) détaillées dans `docs/02_risk_analysis_tde.md`. MFA Authentik identifié comme dette prioritaire — le SPNEGO ne doit pas devenir un contournement.
- **Encodage** : scripts PowerShell 100 % ASCII, splatting (pas de backticks de continuation) — leçons de la rétrospective AD FS (`legacy/docs/00_RETROSPECTIVE_embuches.md`).

## Dette de sécurité à traiter (cible production)

1. CDP LDAP-only sur la chaîne AD CS → ajouter un CDP HTTP avant prod (sinon la vérification de révocation échoue hors domaine).
2. SPOF tier-0 (DC/AC colocalisés) — hérité de l'itération précédente, toujours d'actualité.
3. PKI mono-niveau (racine en ligne) — cible : racine offline + AC émettrice.
4. MFA côté Authentik : le SPNEGO ne doit pas devenir un contournement du MFA prévu (arbitrage à faire, cf. brief Phase 5).

Voir `legacy/docs/00_RETROSPECTIVE_embuches.md` pour l'historique des pièges déjà rencontrés (DNS, egress Docker, NLA, CA, casse issuer, etc.) — plusieurs restent pertinents dans la nouvelle architecture.
