> **⚠️ ARCHIVE — stack non maintenue.** Cette itération (AD FS comme IdP) a été abandonnée au profit d'une architecture Authentik + Kerberos SPNEGO passwordless (OIDCWarden). Elle est conservée ici pour mémoire (rétrospective, pièges rencontrés) mais **ne doit plus servir de base à un déploiement**. Voir le README à la racine du dépôt pour le projet courant.

# Projet — Vaultwarden SSO OIDC ↔ AD FS (déploiement propre, Security by Design)

Ensemble de livrables pour redéployer **proprement, de zéro**, l'intégration SSO OpenID Connect entre Vaultwarden (self-hosted, Docker + Caddy) et AD FS, avec une posture de sécurité intégrée dès la conception.

## Contenu

```
vaultwarden-sso-projet/
├── README.md                              # ce fichier (orchestration)
├── .gitignore                             # exclut secrets, CA, data, annexes
├── docs/
│   └── 00_RETROSPECTIVE_embuches.md       # journal des embûches : causes, résolutions, leçons
├── runbook/
│   └── RUNBOOK_installation_propre.md     # procédure pas-à-pas, couche par couche
└── deploy/
    ├── adfs/
    │   ├── Prepare-AdfsHost.ps1           # prérequis DC/AD FS : DNS, NLA, firewall, cohérence
    │   ├── Export-AdcsRoot.ps1            # export CA racine + empreinte
    │   ├── Deploy-VaultwardenAdfs.ps1     # config AD FS complète (mode groupe / tous)
    │   └── Check-UpnMailInvariant.ps1     # contrôle compensatoire périodique -> SIEM
    ├── docker/
    │   ├── docker-compose.yml             # stack durcie (segmentation, cap_drop, read_only)
    │   ├── Dockerfile                     # image dérivée : CA AD CS + épinglage version
    │   ├── .env.example                   # secrets (à copier en .env, chmod 600)
    │   └── vaultwarden.env.example        # référence variables SSO commentées
    ├── caddy/
    │   └── Caddyfile                      # reverse proxy TLS durci
    ├── firewall/
    │   └── vw-egress-fw.sh                # allow-list egress DOCKER-USER (idempotent)
    └── systemd/
        └── vw-egress-fw.service           # persistance After=docker.service
```

## Ordre de déploiement (couche par couche — une étape, une validation)

| # | Étape | Fichier / commande | Validation |
|---|---|---|---|
| 1 | Prérequis AD/AD FS | `Prepare-AdfsHost.ps1 -DcIp <ip> -ClientSubnet <cidr> -BounceNic` | `NetworkCategory=DomainAuthenticated`, 443 scopé |
| 2 | Export CA racine | `Export-AdcsRoot.ps1 -CaRootCn <cn>` | empreinte SHA-1 notée |
| 3 | Config AD FS | `Deploy-VaultwardenAdfs.ps1 -VaultFqdn <fqdn> -AccessMode Group -GroupName <grp> -ResetSecret` | `ScopeNames` inclut `allatclaims` |
| 4 | Réseau Docker + egress | `docker compose up -d` + `systemctl enable --now vw-egress-fw.service` | `DOCKER-USER` = 4 règles, DROP=0 |
| 5 | TLS | transfert `adcs-root.cer` + vérif empreinte + `docker compose build` | `curl` conteneur → JSON |
| 6 | Vaultwarden | `.env` renseigné + `docker compose up -d` | login test → JIT dans `/admin` |
| 7 | Hygiène | retrait debug, purge logs | plus de jetons dans les logs |

## Choix du modèle d'accès

Le script `Deploy-VaultwardenAdfs.ps1` accepte `-AccessMode` :
- **`Group`** (recommandé) : accès restreint à `-GroupName` (moindre privilège).
- **`Everyone`** : tous les utilisateurs du domaine. **Impose** MFA (`-EnableMfa` auto-activé) + supervision renforcée. Voir l'analyse de risque dans le runbook.

## Points de sécurité clés (rappel)

- **Segmentation** : `backend` interne (ingress Caddy only) + `adfs_egress` filtré (seul AD FS:443).
- **Filtrage symétrique** : firewall Windows inbound scopé ↔ `DOCKER-USER` egress scopé.
- **PKI/TLS** : confiance ajoutée à la CA interne (jamais `--insecure`), version épinglée.
- **IAM** : barrière d'accès à l'IdP (`allatclaims` + politique de groupe), JIT provisioning, matrice de déprovisionnement (pas de SCIM → geste manuel + rotation secrets partagés).
- **Supervision** : audit AD FS event 501, firewall LogBlocked, compteur `VW-EGRESS-DROP` → SIEM.
- **Hygiène debug** : `SSO_DEBUG_TOKENS`/`Log all tokens` jamais en continu + purge des logs.

## Dette de sécurité à traiter (cible production)

1. Séparer les rôles tier-0 (DC/AC/AD FS colocalisés = SPOF).
2. PKI deux niveaux (racine offline).
3. AD FS derrière un WAP en DMZ (ne pas exposer le tier-0 aux clients).
4. Secret client via secret Docker (`SSO_CLIENT_SECRET_FILE`).
5. Règles firewall en GPO (pas en local).
6. Caddy avec certificat de l'AC interne (pas `tls internal`).

Voir `docs/00_RETROSPECTIVE_embuches.md` pour le détail et `runbook/RUNBOOK_installation_propre.md` pour la mise en œuvre.
