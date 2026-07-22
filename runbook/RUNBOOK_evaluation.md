# Runbook d'évaluation — SSO Kerberos passwordless (Phases 1 à 6)

> **Usage** : ce document sert de fil conducteur pour un unique passage de test de bout en bout. Chaque phase liste : les fichiers livrés, les placeholders à substituer, les commandes à exécuter, et le gate attendu. **Ne pas passer à la phase suivante si un gate échoue** — diagnostiquer, pas contourner (cf. règles d'exécution, section finale).
>
> **Ce que ce dépôt ne peut pas faire à votre place** : aucune commande de ce runbook n'a été exécutée contre votre infrastructure réelle (DC `192.168.100.76`, hôte Docker `192.168.100.89`, Authentik). Tout ce qui suit est à exécuter et valider par vous.

## Placeholders à substituer avant de commencer

| Placeholder | Où | Valeur réelle attendue |
|---|---|---|
| `<CLIENT_SUBNET>` | `deploy/authentik/kerberos-sso-blueprint.yaml` | CIDR du LAN intranet (ex. `192.168.100.0/24`) |
| `<AUTHENTIK_IP>` | `deploy/firewall/vw-egress-fw.sh` | IP réelle d'`auth.vaultwardensso.local` |
| `<slug>` | `.env` (`VW_SSO_AUTHORITY`), doc Authentik | slug du Provider OIDC Vaultwarden créé côté Authentik |
| `TargetOuDn` | paramètre de `Deploy-KerberosSSO-GPO.ps1` | DN de l'OU contenant les postes clients |
| Version OIDCWarden | `deploy/docker/Dockerfile` | `v2026.6.4-1` épinglée à la rédaction — **revérifier** sur `hub.docker.com/r/timshel/oidcwarden/tags` avant build, la version peut avoir changé |

## Checklist globale

- [ ] Phase 1 — TLS Caddy
- [ ] Phase 2 — Compte de service + SPN + keytab (DC)
- [ ] Phase 3 — Source Kerberos Authentik
- [ ] Phase 4 — GPO postes clients
- [ ] Phase 5 — Bascule OIDCWarden + TDE
- [ ] Phase 6 — Hygiène et supervision

---

## Phase 1 — TLS Caddy (chaîne AD CS)

**Fichiers** : `deploy/caddy/Caddyfile`, `deploy/docker/docker-compose.yml`, `deploy/docker/Dockerfile`

**Pré-requis manuels** (non livrables du dépôt, secrets) :
1. Placer `vault.crt` (leaf + chaîne) et `vault.key` (chmod 600, owner root) dans `deploy/caddy/certs/`.
2. Placer `adcs-root.crt` (PEM, empreinte SHA-1 vérifiée = `473BAAC9189D52715E3E73CED9BEC691293BED10`) dans `deploy/docker/`.
3. Copier `deploy/docker/.env.example` en `.env`, renseigner `VW_ADMIN_TOKEN`.

**Commandes** :
```bash
cd deploy/docker
docker compose up -d caddy
```

**Gate** :
```bash
openssl s_client -connect vault.vaultwardensso.local:443 -servername vault.vaultwardensso.local </dev/null 2>/dev/null | openssl x509 -noout -issuer
# attendu : issuer = CA AD CS (thumbprint 473B...)

openssl s_client -connect vault.vaultwardensso.local:443 -servername vault.vaultwardensso.local -CAfile <chemin_racine_AD_CS.pem> </dev/null 2>&1 | grep "Verify return code"
# attendu : Verify return code: 0 (ok)
```

**Dette immédiate à solder** :
```bash
docker compose up -d --build vaultwarden
docker exec vaultwarden curl -fsS https://vault.vaultwardensso.local/alive
# attendu : réponse JSON, pas d'erreur "unable to get local issuer certificate"
```

---

## Phase 2 — Compte de service + SPN + keytab (DC)

**Fichier** : `deploy/kerberos/Setup-KerberosSPNEGO-DC.ps1`

**Commande** (sur le DC, PowerShell 5.1 élevé) :
```powershell
.\Setup-KerberosSPNEGO-DC.ps1 -SpnHostname 'auth.vaultwardensso.local' -Realm 'VAULTWARDENSSO.LOCAL' -Domain 'VAULTWARDENSSO'
```

**Gates intégrés au script** (STOP automatique si échec) :
- Anti-doublon SPN avant toute création.
- `msDS-SupportedEncryptionTypes = 24` confirmé après écriture.
- SPN confirmé présent après `setspn -S`.
- `ktpass` : code de sortie vérifié.
- kvno affiché, SHA-256 du keytab affiché.

**Action manuelle requise après le script** :
- Lier une GPO (User Rights Assignment) appliquant `SeDenyInteractiveLogonRight` + `SeDenyRemoteInteractiveLogonRight` au groupe `GG-SvcAccounts-DenyInteractiveLogon`, puis `gpupdate /force`.

**Transfert du keytab (Debian)** :
```bash
smbclient //192.168.100.76/C$ -U Administrator -c 'get authentik.keytab'
sha256sum authentik.keytab
# comparer avec le hash affiché par le script côté DC (Get-FileHash) -> DOIT être identique
chown root:root authentik.keytab && chmod 600 authentik.keytab
```
Puis supprimer `C:\authentik.keytab` du DC une fois l'intégrité confirmée.

**Gate** : `klist` côté DC n'est **pas** suffisant — la validation réelle se fait Phase 3.

---

## Phase 3 — Source Kerberos Authentik

**Fichiers** : `deploy/authentik/kerberos-sso-blueprint.yaml`, `deploy/authentik/README.md`

Suivre `deploy/authentik/README.md` intégralement (substitution `<CLIENT_SUBNET>`, import du blueprint, upload manuel du keytab en base64, vérification `user_matching_mode = username_deny`).

**Gates séquentiels** (détail complet dans le README de la phase) :
- a. `curl --negotiate -u : https://auth.vaultwardensso.local/source/kerberos/kerberos-sso/login/` depuis un poste domaine → `302`.
- b. Navigateur poste domaine → `https://vault.vaultwardensso.local` → aucun formulaire.
- c. Poste hors domaine → formulaire password affiché (fallback).
- d. Logs Authentik → event `login` source `kerberos-sso`, pas de stage password traversé.

---

## Phase 4 — GPO postes clients

**Fichiers** : `deploy/gpo/Deploy-KerberosSSO-GPO.ps1`, `deploy/gpo/firefox-policies.json`, `deploy/gpo/Deploy-BitwardenClients.reg`

**Commande** (RSAT GPMC, ex. depuis le DC) :
```powershell
.\Deploy-KerberosSSO-GPO.ps1 -TargetOuDn 'OU=Postes,DC=vaultwardensso,DC=local' -AuthHostname 'auth.vaultwardensso.local' -VaultBaseUrl 'https://vault.vaultwardensso.local'
```

**Actions manuelles complémentaires** :
- Déployer `firefox-policies.json` vers `%ProgramFiles%\Mozilla Firefox\distribution\policies.json` (GPO Files preference ou script de connexion) si Firefox est présent.
- `Deploy-BitwardenClients.reg` : utilisable en test manuel poste par poste (le GPO script couvre déjà Chrome/Edge/Firefox en registre — le `.reg` est redondant/pratique pour un test isolé).

**Gate** :
```
gpresult /r
```
puis, sur un poste test, DevTools navigateur → vérifier l'en-tête `Authorization: Negotiate` sur la requête vers `auth.vaultwardensso.local`.

Pour Firefox : `about:policies` doit afficher `NegotiateAuth.Trusted` avec l'URL Authentik.

---

## Phase 5 — Bascule OIDCWarden + TDE

**Fichiers** : `deploy/docker/Dockerfile`, `deploy/docker/docker-compose.yml`, `deploy/docker/.env.example`, `deploy/firewall/vw-egress-fw.sh`, `deploy/systemd/vw-egress-fw.service`, `docs/02_risk_analysis_tde.md`

Suivre l'ordre strict décrit dans `docs/02_risk_analysis_tde.md` (backup préalable → build/up avec `SSO_ONLY=false` → Organization + policies TDE → gate device approval → **break-glass avant `SSO_ONLY=true`** → gate final poste vierge).

**Commandes clés** :
```bash
# Backup préalable (adapter au backend DB réel)
pg_dump ... > backup.sql && pg_restore --list backup.sql   # gate : restauration testée à blanc

# Firewall egress (renseigner AUTHENTIK_IP dans vw-egress-fw.sh avant)
sudo cp deploy/firewall/vw-egress-fw.sh /usr/local/sbin/ && sudo chmod 700 /usr/local/sbin/vw-egress-fw.sh
sudo cp deploy/systemd/vw-egress-fw.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now vw-egress-fw.service

cd deploy/docker
docker compose build && docker compose up -d
```

**Gate intermédiaire** : login SSO d'un compte test → flux complet sans régression → compte visible `/admin`.

**Gate TDE** : nouvel utilisateur test → onboarding (master password une fois) → membre de l'org → option "se souvenir de cet appareil" → login N+2 → **aucun master password demandé**.

**Gate break-glass** : compte local hors SSO, hors organization, master password en coffre scellé → login réussi même avec `SSO_ONLY=true` actif.

**Gate final** : poste domaine vierge → session Windows → navigateur → coffre déverrouillé, avec pour seules saisies : email (1ʳᵉ fois), master password (onboarding uniquement), approbation device. Ensuite : zéro saisie.

---

## Phase 6 — Hygiène, supervision

**Fichier** : `docs/03_supervision_siem.md`

Checklist à dérouler après validation de la Phase 5 :
- [ ] Purge des artefacts de debug (`SSO_DEBUG_TOKENS`, keytabs temporaires, captures).
- [ ] Points de collecte SIEM branchés (table complète dans `docs/03_supervision_siem.md`).
- [ ] Rotation des secrets planifiée et documentée (keytab, `SSO_CLIENT_SECRET`, `ADMIN_TOKEN`).
- [ ] Matrice de déprovisionnement mise à jour (couche Device Key ajoutée).

---

## Règles d'exécution (rappel)

1. Une commande à la fois, sortie attendue annoncée, valider avant la suivante.
2. Tout écart entre sortie observée et attendue = STOP + diagnostic, pas de contournement.
3. Aucun secret dans les réponses, les logs, ou les fichiers versionnés — placeholders systématiques (déjà respecté dans les livrables de ce dépôt : aucun `.crt`/`.key`/`.keytab`/`.env` réel n'est commité, cf. `.gitignore`).
4. Versions épinglées partout (Dockerfile OIDCWarden) — revérifier avant chaque build, pas seulement à la rédaction de ce runbook.
