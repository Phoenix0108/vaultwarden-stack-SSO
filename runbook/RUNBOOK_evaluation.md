# Runbook d'évaluation — SSO Kerberos passwordless (Phases 1 à 6)

> **Usage** : ce document sert de fil conducteur pour un unique passage de test de bout en bout. Chaque phase liste : les fichiers livrés, les placeholders à substituer, les **commandes exactes à taper** (💻), les **actions qui restent UI/GUI par nature** (🖱️ — aucune commande fiable ne les remplace, c'est signalé explicitement plutôt que laissé implicite), et le gate attendu. **Ne pas passer à la phase suivante si un gate échoue** — diagnostiquer, pas contourner.
>
> **Ce que ce dépôt ne peut pas faire à votre place** : aucune commande de ce runbook n'a été exécutée contre votre infrastructure réelle (DC `192.168.100.76`, hôte Docker `192.168.100.89`, Authentik). Tout ce qui suit est à exécuter et valider par vous.
>
> **Convention** : `DC>` = à taper sur le DC (PowerShell 5.1 élevé) ; `DEBIAN>` = à taper sur l'hôte Docker (bash) ; `POSTE-TEST>` = à taper sur le poste client de test (PowerShell ou invite de commandes).

## Placeholders à substituer avant de commencer

| Placeholder | Où | Valeur réelle attendue |
|---|---|---|
| `<CLIENT_SUBNET>` | `deploy/authentik/kerberos-sso-blueprint.yaml` | CIDR du LAN intranet (ex. `192.168.100.0/24`) |
| `<AUTHENTIK_IP>` | `deploy/firewall/vw-egress-fw.sh` | IP réelle d'`auth.vaultwardensso.local` |
| `<slug>` | `.env` (`VW_SSO_AUTHORITY`), doc Authentik | slug du Provider OIDC Vaultwarden créé côté Authentik |
| `TargetOuDn` | paramètre de `Deploy-KerberosSSO-GPO.ps1` | DN de l'OU contenant les postes clients |
| Version OIDCWarden | `deploy/docker/Dockerfile` | `v2026.6.4-1` épinglée à la rédaction — **revérifier** sur `hub.docker.com/r/timshel/oidcwarden/tags` avant build |

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

### 1.1 Récupérer et placer les fichiers TLS (DEBIAN, après avoir obtenu vault.crt/vault.key/adcs-root.crt)

Selon le brief, la chaîne est déjà assemblée et vérifiée (empreintes SHA-1 OK) — il reste à la transférer et la monter. Si les fichiers sont déjà sur le DC ou un poste d'admin Windows :

```bash
DEBIAN> smbclient //192.168.100.76/C$ -U Administrator -c 'get vault.crt; get vault.key; get adcs-root.crt'
```

Puis, depuis le répertoire du dépôt :

```bash
DEBIAN> sudo install -o root -g root -m 644 vault.crt  deploy/caddy/certs/vault.crt
DEBIAN> sudo install -o root -g root -m 600 vault.key  deploy/caddy/certs/vault.key
DEBIAN> sudo install -o root -g root -m 644 adcs-root.crt deploy/docker/adcs-root.crt
DEBIAN> rm -f vault.crt vault.key adcs-root.crt   # copies locales transitoires
```

### 1.2 Secrets applicatifs

```bash
DEBIAN> cd deploy/docker
DEBIAN> cp .env.example .env
DEBIAN> chmod 600 .env
DEBIAN> openssl rand -base64 48   # coller le résultat dans .env -> VW_ADMIN_TOKEN=...
DEBIAN> nano .env                 # (ou vi/vim) renseigner VW_ADMIN_TOKEN
```

### 1.3 Déploiement

```bash
DEBIAN> cd deploy/docker
DEBIAN> docker compose up -d caddy
```

### 1.4 Gate

```bash
DEBIAN> openssl s_client -connect vault.vaultwardensso.local:443 -servername vault.vaultwardensso.local </dev/null 2>/dev/null | openssl x509 -noout -issuer
# attendu : issuer = CA AD CS (thumbprint 473B...)

DEBIAN> openssl s_client -connect vault.vaultwardensso.local:443 -servername vault.vaultwardensso.local -CAfile deploy/docker/adcs-root.crt </dev/null 2>&1 | grep "Verify return code"
# attendu : Verify return code: 0 (ok)
```

### 1.5 Dette immédiate à solder (confiance TLS du conteneur)

```bash
DEBIAN> docker compose up -d --build vaultwarden
DEBIAN> docker exec vaultwarden curl -fsS https://vault.vaultwardensso.local/alive
# attendu : réponse JSON, pas d'erreur "unable to get local issuer certificate"
```

---

## Phase 2 — Compte de service + SPN + keytab (DC)

**Fichier** : `deploy/kerberos/Setup-KerberosSPNEGO-DC.ps1`

### 2.1 Exécution du script

```powershell
DC> cd C:\vaultwarden-stack-SSO\deploy\kerberos
DC> .\Setup-KerberosSPNEGO-DC.ps1 -SpnHostname 'auth.vaultwardensso.local' -Realm 'VAULTWARDENSSO.LOCAL' -Domain 'VAULTWARDENSSO'
```

Gates intégrés au script (STOP automatique si échec) : anti-doublon SPN, `msDS-SupportedEncryptionTypes = 24` confirmé, SPN confirmé après `setspn -S`, code de sortie `ktpass` vérifié, kvno affiché, SHA-256 du keytab affiché.

### 2.2 🖱️ Refus de logon interactif (GPO) — pas de commande fiable, action GUI requise

Il n'existe pas de cmdlet dans le module `GroupPolicy` pour les *User Rights Assignments* (`SeDenyInteractiveLogonRight`/`SeDenyRemoteInteractiveLogonRight`) : ce sont des réglages de sécurité (`GptTmpl.inf`) dont l'édition brute en SYSVOL est fragile (désynchronisation possible entre le `Version` de `gpt.ini` et l'attribut `versionNumber` de l'objet GPO en AD, qui provoque une non-application silencieuse). Microsoft recommande la console GPMC (ou l'outil externe `LGPO.exe`). Procédure GUI :

1. `gpmc.msc` → clic droit sur l'OU cible → *Create a GPO in this domain, and Link it here* → nommer `Deny-Interactive-SvcAccounts`.
2. Éditer la GPO → *Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → User Rights Assignment*.
3. *Deny log on locally* → Add User or Group → `GG-SvcAccounts-DenyInteractiveLogon` (groupe créé par le script Phase 2.1).
4. *Deny log on through Remote Desktop Services* → même groupe.

### 2.3 Gate

```powershell
DC> gpupdate /force
```
Gate réel : `klist` côté DC n'est **pas** suffisant — la validation réelle se fait Phase 3.

### 2.4 Transfert du keytab (DEBIAN)

```bash
DEBIAN> smbclient //192.168.100.76/C$ -U Administrator -c 'get authentik.keytab'
DEBIAN> sha256sum authentik.keytab
# comparer avec le hash affiché par le script côté DC (Get-FileHash) -> DOIT être identique
DEBIAN> sudo chown root:root authentik.keytab
DEBIAN> sudo chmod 600 authentik.keytab
```

Puis supprimer le fichier source du DC une fois l'intégrité confirmée :

```bash
DEBIAN> smbclient //192.168.100.76/C$ -U Administrator -c 'del authentik.keytab'
```

---

## Phase 3 — Source Kerberos Authentik

**Fichiers** : `deploy/authentik/kerberos-sso-blueprint.yaml`, `deploy/authentik/README.md`

### 3.1 Substitution du placeholder

```bash
DEBIAN> sed -i 's#<CLIENT_SUBNET>#192.168.100.0/24#' deploy/authentik/kerberos-sso-blueprint.yaml
```

### 3.2 Import du blueprint

```bash
DEBIAN> docker exec -i authentik-server ak import_blueprint < deploy/authentik/kerberos-sso-blueprint.yaml
```
*(adapter le nom du conteneur/serveur Authentik réel — sinon 🖱️ import via Admin → System → Blueprints → Import)*

### 3.3 🖱️ Upload du keytab — action GUI (secret, jamais scriptable vers un tiers)

```bash
DEBIAN> base64 -w0 authentik.keytab > authentik.keytab.b64
```
Coller le contenu de `authentik.keytab.b64` dans Directory → Federation & Social login → *Kerberos SPNEGO SSO* → champ Keytab (GUI Authentik). Puis :
```bash
DEBIAN> shred -u authentik.keytab.b64
```

### 3.4 Vérification (GUI) des champs de la source

🖱️ Confirmer dans l'UI : `spnego_server_name = HTTP/auth.vaultwardensso.local`, `user_matching_mode = username_deny`, `sync_users = false`.

### 3.5 Gates séquentiels

```bash
POSTE-TEST> curl --negotiate -u : https://auth.vaultwardensso.local/source/kerberos/kerberos-sso/login/
# attendu : 302 (pas 401 final)
```

🖱️ b. Navigateur poste domaine → `https://vault.vaultwardensso.local` → aucun formulaire affiché.
🖱️ c. Poste hors domaine → formulaire password affiché (fallback).
🖱️ d. Admin Authentik → Events → un `login` source `kerberos-sso`, sans stage password traversé.

---

## Phase 4 — GPO postes clients

**Fichiers** : `deploy/gpo/Deploy-KerberosSSO-GPO.ps1`, `deploy/gpo/firefox-policies.json`, `deploy/gpo/Deploy-BitwardenClients.reg`

### 4.1 GPO navigateurs (zone Intranet, AuthServerAllowlist, extension Bitwarden)

```powershell
DC> cd C:\vaultwarden-stack-SSO\deploy\gpo
DC> .\Deploy-KerberosSSO-GPO.ps1 -TargetOuDn 'OU=Postes,DC=vaultwardensso,DC=local' -AuthHostname 'auth.vaultwardensso.local' -VaultBaseUrl 'https://vault.vaultwardensso.local'
```

### 4.2 Alternative manuelle poste-par-poste (utile pour le test isolé, évite d'attendre un cycle de réplication GPO)

```powershell
POSTE-TEST> reg import \\192.168.100.76\C$\vaultwarden-stack-SSO\deploy\gpo\Deploy-BitwardenClients.reg
```

### 4.3 Firefox — network.negotiate-auth.trusted-uris (déploiement sur le poste de test)

```powershell
DC> New-Item -ItemType Directory -Force -Path '\\vaultwardensso.local\SYSVOL\vaultwardensso.local\scripts' | Out-Null
DC> Copy-Item -Path C:\vaultwarden-stack-SSO\deploy\gpo\firefox-policies.json -Destination '\\vaultwardensso.local\SYSVOL\vaultwardensso.local\scripts\firefox-policies.json' -Force
```
```powershell
POSTE-TEST> New-Item -ItemType Directory -Force -Path 'C:\Program Files\Mozilla Firefox\distribution' | Out-Null
POSTE-TEST> Copy-Item -Path '\\vaultwardensso.local\SYSVOL\vaultwardensso.local\scripts\firefox-policies.json' -Destination 'C:\Program Files\Mozilla Firefox\distribution\policies.json' -Force
```
Pour un déploiement fleet (pas juste le poste de test), convertir cette copie en GPO Files preference (🖱️ GPMC → User/Computer Configuration → Preferences → Windows Settings → Files) ou en script de démarrage GPO — hors périmètre d'un runbook d'évaluation à un seul poste.

### 4.4 Gate

```powershell
POSTE-TEST> gpupdate /force
POSTE-TEST> gpresult /r
```
🖱️ DevTools navigateur → en-tête `Authorization: Negotiate` sur la requête vers `auth.vaultwardensso.local`.
🖱️ Firefox : `about:policies` → `NegotiateAuth.Trusted` doit lister l'URL Authentik.

---

## Phase 5 — Bascule OIDCWarden + TDE

**Fichiers** : `deploy/docker/Dockerfile`, `deploy/docker/docker-compose.yml`, `deploy/docker/.env.example`, `deploy/firewall/vw-egress-fw.sh`, `deploy/systemd/vw-egress-fw.service`, `docs/02_risk_analysis_tde.md`

### 5.1 Backup préalable

La stack (`docker-compose.yml`) n'a pas de `DATABASE_URL` défini : backend **SQLite** par défaut (`vw-data/db.sqlite3`) — un backup fichier suffit (adapter si vous avez configuré Postgres/MySQL en plus) :

```bash
DEBIAN> cd deploy/docker
DEBIAN> tar czf ../../backup-vw-data-$(date +%Y%m%d-%H%M%S).tar.gz vw-data/
```

Gate — restauration testée à blanc :

```bash
DEBIAN> mkdir -p /tmp/restore-test
DEBIAN> tar xzf backup-vw-data-*.tar.gz -C /tmp/restore-test
DEBIAN> sqlite3 /tmp/restore-test/vw-data/db.sqlite3 "PRAGMA integrity_check;"
# attendu : ok
DEBIAN> rm -rf /tmp/restore-test
```

### 5.2 Firewall egress (renseigner AUTHENTIK_IP avant)

```bash
DEBIAN> sed -i 's/__AUTHENTIK_IP__/<AUTHENTIK_IP_REELLE>/' deploy/firewall/vw-egress-fw.sh
DEBIAN> sudo cp deploy/firewall/vw-egress-fw.sh /usr/local/sbin/
DEBIAN> sudo chmod 700 /usr/local/sbin/vw-egress-fw.sh
DEBIAN> sudo cp deploy/systemd/vw-egress-fw.service /etc/systemd/system/
DEBIAN> sudo systemctl daemon-reload
DEBIAN> sudo systemctl enable --now vw-egress-fw.service
DEBIAN> sudo iptables -L DOCKER-USER -n -v --line-numbers   # gate visuel
```

### 5.3 Compléter .env (Phase 5)

```bash
DEBIAN> nano deploy/docker/.env
# renseigner VW_SSO_CLIENT_ID, VW_SSO_CLIENT_SECRET, VW_SSO_AUTHORITY
# (VW_SSO_AUTHORITY = coller VERBATIM l'issuer depuis
#  https://auth.vaultwardensso.local/application/o/<slug>/.well-known/openid-configuration)
```

### 5.4 Build et déploiement

```bash
DEBIAN> cd deploy/docker
DEBIAN> docker compose build
DEBIAN> docker compose up -d
DEBIAN> docker compose logs -f vaultwarden   # surveiller le démarrage / erreurs SSO_AUTHORITY
```

### 5.5 🖱️ Organization + policies TDE — action GUI (admin OIDCWarden `/admin`)

1. Créer l'Organization cible.
2. Activer policy **Single Organization**.
3. Activer policy **Account Recovery Administration** (auto-enrollment).
4. Mapper le groupe AD (claims groupes Authentik → `SSO_ORGANIZATIONS_*`) pour invitation automatique.

### 5.6 🖱️ Compte break-glass — action GUI, AVANT SSO_ONLY=true

Créer un compte local (email hors domaine dédié), master password fort généré hors ligne et scellé physiquement, **exclu de l'Organization SSO**.

### 5.7 Gates (manuels, navigateur)

🖱️ Login SSO compte test → flux complet sans régression → visible `/admin`.
🖱️ Gate TDE : onboarding → device approval → login N+2 → aucun master password demandé.
🖱️ Gate break-glass : login réussi même après passage à `SSO_ONLY=true`.

### 5.8 Bascule SSO_ONLY (uniquement après 5.7 validé)

```bash
DEBIAN> sed -i 's/SSO_ONLY: "false"/SSO_ONLY: "true"/' deploy/docker/docker-compose.yml
DEBIAN> docker compose up -d vaultwarden
```

---

## Phase 6 — Hygiène, supervision

**Fichier** : `docs/03_supervision_siem.md`

```bash
DEBIAN> shred -u backup-vw-data-*.tar.gz   # si conservé le temps du test uniquement, sinon archiver en lieu sûr
```

```powershell
DC> Clear-History
DC> Remove-Item (Get-PSReadLineOption).HistorySavePath -Force -ErrorAction SilentlyContinue
```

Checklist restante (voir `docs/03_supervision_siem.md` pour le détail) :
- [ ] Points de collecte SIEM branchés (4768/4769 filtrés, events Authentik, `VW-EGRESS-DROP`).
- [ ] Rotation des secrets planifiée (keytab, `SSO_CLIENT_SECRET`, `ADMIN_TOKEN`).
- [ ] Matrice de déprovisionnement mise à jour (couche Device Key).

---

## Règles d'exécution (rappel)

1. Une commande à la fois, sortie attendue annoncée, valider avant la suivante.
2. Tout écart entre sortie observée et attendue = STOP + diagnostic, pas de contournement.
3. Aucun secret dans les réponses, les logs, ou les fichiers versionnés — placeholders systématiques.
4. Versions épinglées partout (Dockerfile OIDCWarden) — revérifier avant chaque build.
5. Les étapes marquées 🖱️ sont GUI par nature (secret binaire, wizard, ou réglage sans cmdlet fiable) — ce n'est pas un oubli, c'est documenté comme tel plutôt que remplacé par une commande fragile.
