# Runbook d'évaluation — SSO Kerberos passwordless (Phases 1 à 6)

> **Usage** : version consolidée pour un déploiement complet en un minimum de passages, en repartant de zéro (DC et hôte Docker). Les commandes de chaque bloc se collent d'une traite sur la machine indiquée. Les **gates** restent des points d'arrêt : vérifier la sortie attendue avant de passer au bloc suivant — un gate qui échoue = diagnostiquer, pas contourner.
>
> **Ce que ce dépôt ne peut pas faire à votre place** : aucune commande de ce runbook n'a été exécutée contre votre infrastructure réelle (DC `192.168.100.76`, hôte Docker `192.168.100.89`, Authentik). Tout ce qui suit est à exécuter et valider par vous.
>
> **Légende des pastilles** : 🔵 = à exécuter sur le **DC** (PowerShell 5.1 élevé, `192.168.100.76`) · 🟢 = à exécuter sur l'**hôte Docker** (bash, `192.168.100.89`) · 🟠 = à exécuter sur un **poste client de test** domain-joined (PowerShell ou invite de commandes). Une étape sans pastille est une lecture/vérification, pas une commande à taper.
>
> **L'hôte Docker (`192.168.100.89`) n'est PAS joint au domaine AD.** Conséquences : aucune résolution DNS automatique vers `vaultwardensso.local`. **Authentik tourne sur cette même VM** (server + worker + PostgreSQL + Redis, dans ce même `docker-compose.yml`) : plus d'IP LAN ni de règle firewall à gérer, Caddy le rejoint directement par nom de service Docker (`authentik-server`). **Tout passe par Caddy** : `vault.*` ET `auth.*` sont résolus en interne par Docker vers le conteneur Caddy (alias réseau sur `backend`). `smbclient` fonctionne sans domain join mais le compte est qualifié par son domaine (`'VAULTWARDENSSO\Administrator'`) ; tout ce qui est SPNEGO/Negotiate (Phase 3, Phase 4) se teste **uniquement depuis un poste 🟠 domain-joined**, jamais depuis le serveur Debian.

## Placeholders à substituer avant de commencer

| Placeholder | Où | Valeur réelle attendue |
|---|---|---|
| `<URL_DU_DEPOT_GIT>` | Phase 1, bloc DEBIAN #1 | URL de clone du dépôt (SSH ou HTTPS selon vos accès) |
| `<CLIENT_SUBNET>` | `deploy/authentik/kerberos-sso-blueprint.yaml` | CIDR du LAN intranet (ex. `192.168.100.0/24`) |
| `PG_PASS` / `AUTHENTIK_SECRET_KEY` | `.env` | générés automatiquement par `install-vault-cert.sh` si laissés au placeholder — aucune saisie manuelle requise |
| `<slug>` | `.env` (`VW_SSO_AUTHORITY`), doc Authentik | slug du Provider OIDC Vaultwarden créé côté Authentik |
| `TargetOuDn` | paramètre de `Deploy-KerberosSSO-GPO.ps1` | DN de l'OU contenant les postes clients |
| Version OIDCWarden | `deploy/docker/Dockerfile` | `v2026.6.4-1` épinglée à la rédaction — **revérifier** sur `hub.docker.com/r/timshel/oidcwarden/tags` avant build |
| `<NomServeur>\<NomCA>` | Phase 1, bloc DC #1 (`certreq -submit -config`) | valeur constatée dans cet environnement : `SRVADTEST\vaultwardensso-srvadtest-CA` (déjà substituée ci-dessous ; revérifier via `certutil -ADCA` si la CA a changé — voir note) |

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

**Hypothèse** : DC et hôte Docker repartent de zéro — aucun dépôt cloné, aucune stack déployée, aucun certificat existant.

> **Raccourci scripté (recommandé)** : `deploy/tls/New-VaultCertDC.ps1` (🔵 DC) et `deploy/tls/install-vault-cert.sh` (🟢 Debian) automatisent l'intégralité des blocs ci-dessous — idempotents, avec retries réseau et vérifications à chaque étape (voir leurs en-têtes). Le script Debian installe aussi ses propres prérequis (clone du dépôt, Docker, smbclient, openssl) s'ils manquent, donc il peut se lancer sur un serveur vraiment vierge. Les blocs manuels qui suivent restent la référence si un script échoue et qu'il faut diagnostiquer étape par étape.
> ```powershell
> # 🔵 DC
> cd C:\vaultwarden-stack-SSO\deploy\tls
> .\New-VaultCertDC.ps1
> ```
> ```bash
> # 🟢 Debian -- si le dépôt n'est pas encore cloné, ajouter REPO_URL=<url_du_depot> devant.
> # Credentials SMB interactifs par defaut, ou SMB_PASSWORD=... pour un usage non interactif.
> ./deploy/tls/install-vault-cert.sh
> # ou, sur un serveur vierge, en une commande (copier d'abord ce fichier sur le serveur) :
> # REPO_URL=<url_du_depot> ./install-vault-cert.sh
> ```

### 🔵 DC — bloc 1 : générer la CSR, l'accepter, exporter clé + racine

Tout dans **la même session PowerShell élevée, sans interruption** (un écart de session entre `-new` et `-accept` rend le certificat orphelin — vécu en pratique). Le certificat porte deux SAN (`vault.*` et `auth.*`) : **tout passe par Caddy**, y compris `auth.vaultwardensso.local` (Caddy reverse-proxie vers le vrai Authentik) — un seul certificat suffit pour les deux vhosts.

```powershell
@"
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
_continue_ = "dns=auth.vaultwardensso.local&"
"@ | Out-File -Encoding ascii vault-new.inf

certreq -new -machine vault-new.inf vault-new.csr
certreq -submit -attrib "CertificateTemplate:WebServer" -config "SRVADTEST\vaultwardensso-srvadtest-CA" vault-new.csr vault-new.cer
certreq -accept -machine vault-new.cer

$thumb = (Get-PfxCertificate -FilePath C:\vault-new.cer).Thumbprint
$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $thumb } | Select-Object -First 1
if (-not $cert) { throw "Certificat non trouve dans Cert:\LocalMachine\My juste apres -accept" }

$pfxPassPlain = -join ((48..57)+(65..90)+(97..122) | Get-Random -Count 24 | ForEach-Object { [char]$_ })
$pfxPass = ConvertTo-SecureString -String $pfxPassPlain -AsPlainText -Force
Export-PfxCertificate -Cert $cert -FilePath C:\vault-new.pfx -Password $pfxPass
(New-Object System.Security.Cryptography.X509Certificates.X509Certificate2('C:\vault-new.pfx', $pfxPassPlain)).Subject
# attendu : CN=vault.vaultwardensso.local -- si ca erreur ici, le probleme est dans l'export, pas le transfert
Set-Content -Path C:\vault-new.pfxpass.txt -Value $pfxPassPlain -NoNewline -Encoding ascii

Export-Certificate -Cert (Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Thumbprint -eq '473BAAC9189D52715E3E73CED9BEC691293BED10' } | Select-Object -First 1) -FilePath C:\adcs-root.cer -Type CERT
```

Notes utiles si un point coince :
- `certutil -ADCA` : re-decouvrir `<NomServeur>\<NomCA>` si la CA a change (pas de ligne litterale `"Config:"` dans sa sortie ; reconstruire depuis `cACertificateDN` = nom de la CA, et l'entree ACL `<DOMAINE>\<NOM_MACHINE>$` = nom de la machine CA).
- `-submit` n'accepte **pas** `-machine` sur ce build (contexte deja fixe par `-new -machine`) ; `-accept` et `-new` si.
- `Get-PfxCertificate` n'a pas de parametre `-Password` sur ce PowerShell 5.1 — d'ou le constructeur .NET `X509Certificate2` pour la verification.
- Le PFX est chiffre en 3DES/SHA1 (legacy) par ce Server 2016 — geree cote Debian avec `-legacy` plus bas, pas d'action a faire ici.

### 🟢 DEBIAN — bloc 1 : dépôt + Docker

```bash
git clone <URL_DU_DEPOT_GIT> vaultwarden-stack-SSO
cd vaultwarden-stack-SSO
git checkout claude/sso-kerberos-vaultwarden-ad-rzg3w0
docker --version && docker compose version
# attendu : les deux commandes repondent (pas de "command not found") - sinon voir bloc optionnel ci-dessous
```

Optionnel, uniquement si Docker n'est pas installé :

```bash
curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker.gpg] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
sudo systemctl enable --now docker
```

### 🟢 DEBIAN — bloc 2 : récupérer, convertir, assembler, installer la chaîne TLS

Depuis la racine du dépôt (position courante après le bloc 1 ci-dessus — pas de `cd` supplémentaire) :

```bash
smbclient //192.168.100.76/C$ -U 'VAULTWARDENSSO\Administrator' -c 'get vault-new.pfx; get vault-new.pfxpass.txt; get vault-new.cer; get adcs-root.cer'

# certreq -submit sans -binary sort le certificat en Base64 (PEM), pas en DER -> pas d'-inform der ici
openssl x509 -in vault-new.cer -out vault-new.pem
openssl x509 -in vault-new.pem -noout -subject -ext subjectAltName
# attendu : vault.vaultwardensso.local ET auth.vaultwardensso.local presents dans le SAN -- STOP si l'un des deux manque

# Export-Certificate -Type CERT sort en DER brut (different de certreq -submit) -> -inform der ici
openssl x509 -inform der -in adcs-root.cer -out adcs-root.pem
openssl x509 -in adcs-root.pem -noout -fingerprint -sha1
# attendu : 473BAAC9189D52715E3E73CED9BEC691293BED10

# PFX chiffre en 3DES/SHA1 (legacy) par Server 2016 -> -legacy obligatoire sur OpenSSL 3.x
openssl pkcs12 -legacy -in vault-new.pfx -nocerts -nodes -out vault.key -passin file:vault-new.pfxpass.txt
cat vault-new.pem adcs-root.pem > vault.crt

sudo install -o root -g root -m 644 vault.crt     deploy/caddy/certs/vault.crt
sudo install -o root -g root -m 600 vault.key     deploy/caddy/certs/vault.key
sudo install -o root -g root -m 644 adcs-root.pem deploy/docker/adcs-root.crt

rm -f vault.crt vault.key vault-new.pfx vault-new.pfxpass.txt vault-new.cer vault-new.pem adcs-root.cer adcs-root.pem
```

Si `-legacy` renvoie `unknown option`/`provider "legacy" not found` (module absent du paquet openssl) : remplacer par `openssl pkcs12 -provider legacy -provider default ...` (mêmes autres options).

### 🔵 DC — bloc 2 : purger les fichiers transitoires

```powershell
Remove-Item C:\vault-new.pfx, C:\vault-new.pfxpass.txt, C:\vault-new.cer, C:\vault-new.csr, C:\vault-new.inf, C:\adcs-root.cer -Force -ErrorAction SilentlyContinue
```

### 🟢 DEBIAN — bloc 3 : secrets, déploiement, résolution locale

```bash
cd deploy/docker
cp .env.example .env
chmod 600 .env
openssl rand -base64 48   # coller le resultat dans .env -> VW_ADMIN_TOKEN=...
nano .env                 # renseigner VW_ADMIN_TOKEN

mkdir -p vw-data ../caddy/logs   # deploy/caddy/logs, PAS deploy/docker/caddy/logs (sibling, pas enfant)
docker compose up -d caddy

# hote non domain-joined : pas de DNS pour son propre FQDN
echo "127.0.0.1 vault.vaultwardensso.local" | sudo tee -a /etc/hosts
```

### 🟢 DEBIAN — Gate Phase 1

```bash
openssl s_client -connect vault.vaultwardensso.local:443 -servername vault.vaultwardensso.local </dev/null 2>/dev/null | openssl x509 -noout -issuer
# attendu : issuer = CA AD CS (thumbprint 473B...)

openssl s_client -connect vault.vaultwardensso.local:443 -servername vault.vaultwardensso.local -CAfile deploy/docker/adcs-root.crt </dev/null 2>&1 | grep "Verify return code"
# attendu : Verify return code: 0 (ok)

docker compose up -d --build vaultwarden
docker exec vaultwarden curl -fsS https://vault.vaultwardensso.local/alive
# attendu : reponse JSON -- resolution interne via l'alias reseau Docker sur "backend", pas de DNS/hosts necessaire cote conteneur
```

---

## Phase 2 — Compte de service + SPN + keytab (DC)

**Fichier** : `deploy/kerberos/Setup-KerberosSPNEGO-DC.ps1`

### 🔵 DC

```powershell
cd C:\vaultwarden-stack-SSO\deploy\kerberos
.\Setup-KerberosSPNEGO-DC.ps1 -SpnHostname 'auth.vaultwardensso.local' -Realm 'VAULTWARDENSSO.LOCAL' -Domain 'VAULTWARDENSSO'
```

Gates intégrés au script (STOP automatique si échec) : anti-doublon SPN, `msDS-SupportedEncryptionTypes = 24` confirmé, SPN confirmé après `setspn -S`, code de sortie `ktpass` vérifié, kvno affiché, SHA-256 du keytab affiché.

### 🖱️ Refus de logon interactif (GPO) — pas de commande fiable, action GUI requise

Pas de cmdlet dans le module `GroupPolicy` pour les *User Rights Assignments* — édition brute SYSVOL fragile (désync `gpt.ini`/`versionNumber`). Sur le DC via `gpmc.msc` :
1. Clic droit sur l'OU cible → *Create a GPO in this domain, and Link it here* → nommer `Deny-Interactive-SvcAccounts`.
2. *Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → User Rights Assignment*.
3. *Deny log on locally* + *Deny log on through Remote Desktop Services* → Add → `GG-SvcAccounts-DenyInteractiveLogon`.

### 🔵 DC — Gate

```powershell
gpupdate /force
```
`klist` côté DC n'est **pas** suffisant — la validation réelle se fait Phase 3.

### 🟢 DEBIAN — Transfert du keytab

```bash
smbclient //192.168.100.76/C$ -U 'VAULTWARDENSSO\Administrator' -c 'get authentik.keytab'
sha256sum authentik.keytab
# comparer avec le hash affiche par le script cote DC (Get-FileHash) -> DOIT etre identique
sudo chown root:root authentik.keytab
sudo chmod 600 authentik.keytab
smbclient //192.168.100.76/C$ -U 'VAULTWARDENSSO\Administrator' -c 'del authentik.keytab'
```

---

## Phase 2bis — Source LDAP (provisioning des comptes, prérequis Phase 3/5)

**Fichier** : `deploy/kerberos/Setup-LDAPBind-DC.ps1`. Prérequis longtemps implicite ("une source LDAP existante") qui n'existe pas sur un domaine reparti de zéro — ce bloc la crée.

### 🔵 DC

```powershell
cd C:\vaultwarden-stack-SSO\deploy\kerberos
.\Setup-LDAPBind-DC.ps1 -Realm 'VAULTWARDENSSO.LOCAL' -Domain 'VAULTWARDENSSO'
```

Crée (idempotent) `OU=Vaultwarden` (périmètre à peupler avec les vrais comptes à synchroniser) et le compte de bind `svc-authentik-ldap` (lecture seule, deny-interactive-logon, aucune délégation). Mot de passe écrit dans `C:\authentik-ldap-bind.txt` (ACL restreinte, jamais affiché).

### 🟢 DEBIAN — transfert

```bash
smbclient //192.168.100.76/C$ -U 'VAULTWARDENSSO\Administrator' -c 'get authentik-ldap-bind.txt'
openssl s_client -connect 192.168.100.76:636 -CAfile deploy/docker/adcs-root.crt </dev/null 2>&1 | grep "Verify return code"
# attendu : Verify return code: 0 -- sinon ne pas configurer la Source LDAP en LDAPS tant que ce n'est pas corrige
```

### 🖱️ Source LDAP — action GUI (secret, jamais scriptable vers un tiers)

Directory → Federation & Social login → Create → **LDAP Source** : Server URI `ldaps://192.168.100.76:636`, Bind CN = Bind DN affiché par le script, Bind Password = contenu de `authentik-ldap-bind.txt`, Base DN `OU=Vaultwarden,DC=vaultwardensso,DC=local`. Détails complets : `deploy/authentik/README.md` §0.

### 🟢 DEBIAN — purge

```bash
shred -u authentik-ldap-bind.txt
```

### Gate

🖱️ Bouton "Sync" de la Source LDAP dans l'admin Authentik → pas d'erreur, comptes de `OU=Vaultwarden` visibles dans Directory → Users.

---

## Phase 3 — Source Kerberos Authentik

**Fichiers** : `deploy/authentik/kerberos-sso-blueprint.yaml`, `deploy/authentik/README.md`

### 🟢 DEBIAN

```bash
sed -i 's#<CLIENT_SUBNET>#192.168.100.0/24#' deploy/authentik/kerberos-sso-blueprint.yaml
docker exec -i authentik-server ak import_blueprint < deploy/authentik/kerberos-sso-blueprint.yaml
# authentik-server = nom du service Docker (meme VM, meme docker-compose.yml) -- pas d'adaptation necessaire

base64 -w0 authentik.keytab > authentik.keytab.b64
```

### 🖱️ Upload du keytab — action GUI (secret, jamais scriptable vers un tiers)

Coller le contenu de `authentik.keytab.b64` dans Directory → Federation & Social login → *Kerberos SPNEGO SSO* → champ Keytab. Puis confirmer dans l'UI : `spnego_server_name = HTTP/auth.vaultwardensso.local`, `user_matching_mode = username_deny`, `sync_users = false`.

### 🟢 DEBIAN — purge

```bash
shred -u authentik.keytab.b64
```

### Gates séquentiels

🟠 :
```bash
curl --negotiate -u : https://auth.vaultwardensso.local/source/kerberos/kerberos-sso/
# attendu : 302 (pas 401 final)
```

🖱️ Navigateur poste domaine → `https://vault.vaultwardensso.local` → aucun formulaire affiché. 🖱️ Poste hors domaine → formulaire password affiché (fallback). 🖱️ Admin Authentik → Events → un `login` source `kerberos-sso`, sans stage password traversé.

---

## Phase 4 — GPO postes clients

**Fichiers** : `deploy/gpo/Deploy-KerberosSSO-GPO.ps1`, `deploy/gpo/firefox-policies.json`, `deploy/gpo/Deploy-BitwardenClients.reg`

### 🔵 DC

```powershell
cd C:\vaultwarden-stack-SSO\deploy\gpo
.\Deploy-KerberosSSO-GPO.ps1 -TargetOuDn 'OU=Postes,DC=vaultwardensso,DC=local' -AuthHostname 'auth.vaultwardensso.local' -VaultBaseUrl 'https://vault.vaultwardensso.local'

New-Item -ItemType Directory -Force -Path '\\vaultwardensso.local\SYSVOL\vaultwardensso.local\scripts' | Out-Null
Copy-Item -Path C:\vaultwarden-stack-SSO\deploy\gpo\firefox-policies.json -Destination '\\vaultwardensso.local\SYSVOL\vaultwardensso.local\scripts\firefox-policies.json' -Force
```

### 🟠 Poste de test

```powershell
reg import \\192.168.100.76\C$\vaultwarden-stack-SSO\deploy\gpo\Deploy-BitwardenClients.reg

New-Item -ItemType Directory -Force -Path 'C:\Program Files\Mozilla Firefox\distribution' | Out-Null
Copy-Item -Path '\\vaultwardensso.local\SYSVOL\vaultwardensso.local\scripts\firefox-policies.json' -Destination 'C:\Program Files\Mozilla Firefox\distribution\policies.json' -Force

gpupdate /force
gpresult /r
```

Pour un déploiement fleet (pas juste le poste de test), convertir la copie Firefox en GPO Files preference (🖱️ GPMC → Preferences → Windows Settings → Files) — hors périmètre d'une évaluation à un seul poste.

### Gate

🖱️ DevTools navigateur → en-tête `Authorization: Negotiate` sur la requête vers `auth.vaultwardensso.local`. 🖱️ Firefox : `about:policies` → `NegotiateAuth.Trusted` doit lister l'URL Authentik.

🖱️ Signet géré (Chrome `chrome://policy` / Edge `edge://policy` → `ManagedBookmarks`/`ManagedFavorites`, Firefox `about:policies` → `Bookmarks`) : cliquer le signet "Vaultwarden (SSO)" → aucun écran email/identifiant affiché, redirection SPNEGO immédiate vers `https://vault.vaultwardensso.local/#/sso?identifier=vaultwardensso`. Ce lien fonctionne indépendamment de `SSO_ONLY` (c'est un raccourci client, pas une restriction serveur) — testable dès maintenant en le collant manuellement dans la barre d'adresse, sans attendre le déploiement GPO fleet.

---

## Phase 5 — Bascule OIDCWarden + TDE

**Fichiers** : `deploy/docker/Dockerfile`, `deploy/docker/docker-compose.yml`, `deploy/docker/.env.example`, `docs/02_risk_analysis_tde.md`

### 🟢 DEBIAN — bloc 1 : backup, secrets

```bash
cd deploy/docker
tar czf ../../backup-vw-data-$(date +%Y%m%d-%H%M%S).tar.gz vw-data/
mkdir -p /tmp/restore-test
tar xzf ../../backup-vw-data-*.tar.gz -C /tmp/restore-test
sqlite3 /tmp/restore-test/vw-data/db.sqlite3 "PRAGMA integrity_check;"
# attendu : ok
rm -rf /tmp/restore-test

nano .env
# renseigner VW_SSO_CLIENT_ID, VW_SSO_CLIENT_SECRET, VW_SSO_AUTHORITY
# (VW_SSO_AUTHORITY = coller VERBATIM l'issuer depuis .../application/o/<slug>/.well-known/openid-configuration)
# PG_PASS / AUTHENTIK_SECRET_KEY deja generes par install-vault-cert.sh en Phase 1 -- rien a faire ici
```

### 🟢 DEBIAN — bloc 2 : build et déploiement

```bash
cd deploy/docker
docker compose build
docker compose up -d
docker compose logs -f vaultwarden   # surveiller le demarrage / erreurs SSO_AUTHORITY
```

### 🖱️ Organization + policies TDE, break-glass — actions GUI (admin OIDCWarden `/admin`)

1. Créer l'Organization cible, activer **Single Organization** puis **Account Recovery Administration** (auto-enrollment), mapper le groupe AD.
2. **Avant** de passer `SSO_ONLY=true` : créer un compte break-glass local (email hors domaine dédié), master password fort scellé, exclu de l'Organization SSO.

### Gates (manuels, navigateur)

🖱️ Login SSO compte test → flux complet sans régression → visible `/admin`. 🖱️ Gate TDE : onboarding → device approval → login N+2 → aucun master password demandé. 🖱️ Gate break-glass : login réussi même après passage à `SSO_ONLY=true`.

### 🟢 DEBIAN — Bascule SSO_ONLY (uniquement après les gates ci-dessus validés)

```bash
sed -i 's/SSO_ONLY: "false"/SSO_ONLY: "true"/' deploy/docker/docker-compose.yml
docker compose up -d vaultwarden
```

---

## Phase 6 — Hygiène, supervision

**Fichier** : `docs/03_supervision_siem.md`

```bash
shred -u ../../backup-vw-data-*.tar.gz   # chemin relatif a deploy/docker (cwd apres Phase 5) ; adapter si vous avez change de repertoire -- si conserve le temps du test uniquement, sinon archiver en lieu sur avant de supprimer
```

🔵 :
```powershell
Clear-History
Remove-Item (Get-PSReadLineOption).HistorySavePath -Force -ErrorAction SilentlyContinue
```

Checklist restante (voir `docs/03_supervision_siem.md` pour le détail) :
- [ ] Points de collecte SIEM branchés (4768/4769 filtrés, events Authentik, `VW-EGRESS-DROP`).
- [ ] Rotation des secrets planifiée (keytab, `SSO_CLIENT_SECRET`, `ADMIN_TOKEN`).
- [ ] Matrice de déprovisionnement mise à jour (couche Device Key).

---

## Règles d'exécution (rappel)

1. Chaque bloc se colle d'une traite sur la machine indiquée par sa pastille ; un **gate** reste un point d'arrêt — vérifier la sortie attendue avant de passer au bloc suivant.
2. Tout écart entre sortie observée et attendue = STOP + diagnostic, pas de contournement.
3. Aucun secret dans les réponses, les logs, ou les fichiers versionnés — placeholders systématiques.
4. Versions épinglées partout (Dockerfile OIDCWarden) — revérifier avant chaque build.
5. Les étapes marquées 🖱️ sont GUI par nature (secret binaire, wizard, ou réglage sans cmdlet fiable).
