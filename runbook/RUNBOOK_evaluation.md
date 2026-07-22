# Runbook d'évaluation — SSO Kerberos passwordless (Phases 1 à 6)

> **Usage** : ce document sert de fil conducteur pour un unique passage de test de bout en bout. Chaque phase liste : les fichiers livrés, les placeholders à substituer, les **commandes exactes à taper** (💻), les **actions qui restent UI/GUI par nature** (🖱️ — aucune commande fiable ne les remplace, c'est signalé explicitement plutôt que laissé implicite), et le gate attendu. **Ne pas passer à la phase suivante si un gate échoue** — diagnostiquer, pas contourner.
>
> **Ce que ce dépôt ne peut pas faire à votre place** : aucune commande de ce runbook n'a été exécutée contre votre infrastructure réelle (DC `192.168.100.76`, hôte Docker `192.168.100.89`, Authentik). Tout ce qui suit est à exécuter et valider par vous.
>
> **Convention** : `DC>` = à taper sur le DC (PowerShell 5.1 élevé) ; `DEBIAN>` = à taper sur l'hôte Docker (bash) ; `POSTE-TEST>` = à taper sur le poste client de test (PowerShell ou invite de commandes).
>
> **L'hôte Docker (`192.168.100.89`) n'est PAS joint au domaine AD.** Conséquences traitées dans ce runbook :
> - Aucune résolution DNS automatique vers `vaultwardensso.local` : les FQDN nécessaires sont soit résolus en interne par Docker (alias réseau `caddy`↔`vault.vaultwardensso.local`), soit forcés en statique (`/etc/hosts` local, `extra_hosts` dans `docker-compose.yml`) — jamais par un changement du résolveur DNS système (évite la fuite OPSEC de noms internes vers un résolveur public, cf. `legacy/docs/00_RETROSPECTIVE_embuches.md` piège #1).
> - `smbclient` fonctionne sans domain join (authentification NTLM explicite) mais le nom de compte est qualifié par son domaine (`'VAULTWARDENSSO\Administrator'`) pour éviter toute ambiguïté de royaume.
> - Tout ce qui est SPNEGO/Negotiate (Phase 3, Phase 4) se teste **uniquement depuis un `POSTE-TEST` domain-joined** — jamais depuis le serveur Debian, qui n'a et n'aura pas de TGT Kerberos.

## Placeholders à substituer avant de commencer

| Placeholder | Où | Valeur réelle attendue |
|---|---|---|
| `<CLIENT_SUBNET>` | `deploy/authentik/kerberos-sso-blueprint.yaml` | CIDR du LAN intranet (ex. `192.168.100.0/24`) |
| `<AUTHENTIK_IP>` / `VW_AUTHENTIK_IP` | `deploy/firewall/vw-egress-fw.sh` **et** `.env` (`VW_AUTHENTIK_IP`) | IP réelle d'`auth.vaultwardensso.local` — même valeur aux deux endroits, hôte non domain-joined donc pas de résolution DNS AD automatique |
| `<slug>` | `.env` (`VW_SSO_AUTHORITY`), doc Authentik | slug du Provider OIDC Vaultwarden créé côté Authentik |
| `TargetOuDn` | paramètre de `Deploy-KerberosSSO-GPO.ps1` | DN de l'OU contenant les postes clients |
| Version OIDCWarden | `deploy/docker/Dockerfile` | `v2026.6.4-1` épinglée à la rédaction — **revérifier** sur `hub.docker.com/r/timshel/oidcwarden/tags` avant build |
| `<URL_DU_DEPOT_GIT>` | Phase 1.0a | URL de clone du dépôt (SSH ou HTTPS selon vos accès) |
| `<CA-CommonName>` | Phase 1.1 Option B (`certreq -submit -config`) | `Get-CATransaction`/`certutil -CAInfo` sur le DC donne `<NomServeur>\<NomCA>` exact |
| `<mot_de_passe_temporaire_export>` | Phase 1.1 Option B | mot de passe fort, transmis hors bande, à usage unique pour le PFX (jamais dans un fichier versionné) |

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

> **Hypothèse de cette version** : le serveur Docker (`192.168.100.89`) est **repartu de zéro** — aucun dépôt cloné, aucune stack `docker compose` déployée, aucun certificat présent. Docker Engine + le plugin Compose sont supposés déjà installés sur l'OS (Debian 13) ; sinon voir 1.0b.

### 1.0a Provisionner le dépôt sur le serveur reset

```bash
DEBIAN> git clone <URL_DU_DEPOT_GIT> vaultwarden-stack-SSO
DEBIAN> cd vaultwarden-stack-SSO
DEBIAN> git checkout claude/sso-kerberos-vaultwarden-ad-rzg3w0
DEBIAN> docker --version && docker compose version
# attendu : les deux commandes répondent (pas de "command not found")
```

### 1.0b Si Docker n'est pas installé (à sauter sinon)

```bash
DEBIAN> curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker.gpg
DEBIAN> echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker.gpg] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list
DEBIAN> sudo apt-get update
DEBIAN> sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
DEBIAN> sudo systemctl enable --now docker
```

### 1.1 Obtenir la chaîne TLS (vault.crt + vault.key + adcs-root.crt)

**Option A — le certificat a déjà été émis/assemblé ailleurs** (sur le DC ou un poste d'admin Windows, non affecté par le reset du serveur Vaultwarden) :

```bash
DEBIAN> smbclient //192.168.100.76/C$ -U 'VAULTWARDENSSO\Administrator' -c 'get vault.crt; get vault.key; get adcs-root.crt'
```

**Option B — le certificat n'existe plus nulle part : réémission complète depuis zéro** (à exécuter sur le DC, seul endroit disposant nativement de l'outillage PKI Windows) :

```powershell
DC> @"
[Version]
Signature="`$Windows NT`$"
[NewRequest]
Subject = "CN=vault.vaultwardensso.local"
KeyLength = 2048
KeySpec = 1
Exportable = TRUE
MachineKeySet = TRUE
SMIME = FALSE
PrivateKeyArchive = FALSE
UserProtected = FALSE
UseExistingKeySet = FALSE
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
ProviderType = 12
RequestType = PKCS10
KeyUsage = 0xa0
[EnhancedKeyUsageExtension]
OID=1.3.6.1.5.5.7.3.1
[Extensions]
2.5.29.17 = "{text}"
_continue_ = "dns=vault.vaultwardensso.local&"
"@ | Out-File -Encoding ascii vault.inf

DC> certreq -new vault.inf vault.csr
DC> certreq -submit -attrib "CertificateTemplate:WebServer" -config "192.168.100.76\<CA-CommonName>" vault.csr vault.cer
DC> certreq -accept vault.cer
```

Exporter la clé privée + le certificat (le compte utilisé doit avoir accès au magasin machine où la clé a été générée) :

```powershell
DC> $pfxPass = ConvertTo-SecureString -String "<mot_de_passe_temporaire_export>" -AsPlainText -Force
DC> $cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN=vault.vaultwardensso.local" } | Select-Object -First 1
DC> Export-PfxCertificate -Cert $cert -FilePath C:\vault.pfx -Password $pfxPass
DC> Export-Certificate -Cert (Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Thumbprint -eq '473BAAC9189D52715E3E73CED9BEC691293BED10' }) -FilePath C:\adcs-root.cer -Type CERT
```

Transférer puis convertir côté Debian (mot de passe PFX transmis hors bande, jamais dans ce runbook) :

```bash
DEBIAN> smbclient //192.168.100.76/C$ -U 'VAULTWARDENSSO\Administrator' -c 'get vault.pfx; get adcs-root.cer'
DEBIAN> openssl pkcs12 -in vault.pfx -nocerts -nodes -out vault.key
DEBIAN> openssl pkcs12 -in vault.pfx -clcerts -nokeys -out vault.crt
DEBIAN> openssl x509 -inform der -in adcs-root.cer -out adcs-root.crt
DEBIAN> openssl x509 -in adcs-root.crt -noout -fingerprint -sha1
# attendu : 473BAAC9189D52715E3E73CED9BEC691293BED10 (comparer à la valeur de contexte)
```

Puis, côté DC, supprimer les fichiers transitoires (`vault.pfx`, `vault.cer`, `vault.csr`, `vault.inf`, `adcs-root.cer` — la clé privée exportée est un secret) :

```powershell
DC> Remove-Item C:\vault.pfx, C:\vault.cer, C:\vault.csr, C:\vault.inf, C:\adcs-root.cer -Force
```

### 1.2 Placer les fichiers dans le dépôt (DEBIAN)

```bash
DEBIAN> cd vaultwarden-stack-SSO
DEBIAN> sudo install -o root -g root -m 644 vault.crt  deploy/caddy/certs/vault.crt
DEBIAN> sudo install -o root -g root -m 600 vault.key  deploy/caddy/certs/vault.key
DEBIAN> sudo install -o root -g root -m 644 adcs-root.crt deploy/docker/adcs-root.crt
DEBIAN> rm -f vault.crt vault.key vault.pfx adcs-root.crt adcs-root.cer   # copies locales transitoires
```

### 1.3 Secrets applicatifs

```bash
DEBIAN> cd deploy/docker
DEBIAN> cp .env.example .env
DEBIAN> chmod 600 .env
DEBIAN> openssl rand -base64 48   # coller le résultat dans .env -> VW_ADMIN_TOKEN=...
DEBIAN> nano .env                 # (ou vi/vim) renseigner VW_ADMIN_TOKEN
```

### 1.4 Déploiement

```bash
DEBIAN> cd deploy/docker
DEBIAN> mkdir -p vw-data caddy/logs   # bind mounts attendus par docker-compose.yml, absents sur un serveur reset
DEBIAN> docker compose up -d caddy
```

### 1.5 Résolution locale pour les gates (hôte non domain-joined)

Le shell Debian n'a pas de DNS lui donnant `vault.vaultwardensso.local` (le host n'est pas membre du domaine). Sans entrée statique, `openssl s_client -connect vault.vaultwardensso.local:443` échoue à résoudre alors même que Caddy écoute bien sur cette machine :

```bash
DEBIAN> echo "127.0.0.1 vault.vaultwardensso.local" | sudo tee -a /etc/hosts
```

### 1.6 Gate

```bash
DEBIAN> openssl s_client -connect vault.vaultwardensso.local:443 -servername vault.vaultwardensso.local </dev/null 2>/dev/null | openssl x509 -noout -issuer
# attendu : issuer = CA AD CS (thumbprint 473B...)

DEBIAN> openssl s_client -connect vault.vaultwardensso.local:443 -servername vault.vaultwardensso.local -CAfile deploy/docker/adcs-root.crt </dev/null 2>&1 | grep "Verify return code"
# attendu : Verify return code: 0 (ok)
```

### 1.7 Dette immédiate à solder (confiance TLS du conteneur)

Le conteneur `vaultwarden` résout `vault.vaultwardensso.local` en interne via l'alias réseau Docker posé sur `caddy` (`deploy/docker/docker-compose.yml`, réseau `backend`) — **pas** besoin de DNS ni de `/etc/hosts` côté conteneur, ça fonctionne même hôte non domain-joined :

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
DEBIAN> smbclient //192.168.100.76/C$ -U 'VAULTWARDENSSO\Administrator' -c 'get authentik.keytab'
DEBIAN> sha256sum authentik.keytab
# comparer avec le hash affiché par le script côté DC (Get-FileHash) -> DOIT être identique
DEBIAN> sudo chown root:root authentik.keytab
DEBIAN> sudo chmod 600 authentik.keytab
```

Puis supprimer le fichier source du DC une fois l'intégrité confirmée :

```bash
DEBIAN> smbclient //192.168.100.76/C$ -U 'VAULTWARDENSSO\Administrator' -c 'del authentik.keytab'
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

### 5.2 Firewall egress + résolution Authentik (hôte non domain-joined : IP statique requise aux deux endroits)

`<AUTHENTIK_IP_REELLE>` doit être la **même valeur** dans `vw-egress-fw.sh` (règle iptables) et dans `.env` (`VW_AUTHENTIK_IP`, utilisé par `extra_hosts` dans `docker-compose.yml`) :

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
# renseigner VW_SSO_CLIENT_ID, VW_SSO_CLIENT_SECRET, VW_SSO_AUTHORITY, VW_AUTHENTIK_IP
# (VW_SSO_AUTHORITY = coller VERBATIM l'issuer depuis
#  https://auth.vaultwardensso.local/application/o/<slug>/.well-known/openid-configuration)
# (VW_AUTHENTIK_IP = meme IP que <AUTHENTIK_IP_REELLE> ci-dessus - hote non domain-joined,
#  pas de DNS AD automatique pour resoudre auth.vaultwardensso.local depuis le conteneur)
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
