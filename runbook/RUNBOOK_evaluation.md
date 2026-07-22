# Runbook d'évaluation — SSO Kerberos passwordless (Phases 1 à 6)

> **Usage** : ce document sert de fil conducteur pour un unique passage de test de bout en bout. Chaque phase liste : les fichiers livrés, les placeholders à substituer, les **commandes exactes à taper** (💻), les **actions qui restent UI/GUI par nature** (🖱️ — aucune commande fiable ne les remplace, c'est signalé explicitement plutôt que laissé implicite), et le gate attendu. **Ne pas passer à la phase suivante si un gate échoue** — diagnostiquer, pas contourner.
>
> **Ce que ce dépôt ne peut pas faire à votre place** : aucune commande de ce runbook n'a été exécutée contre votre infrastructure réelle (DC `192.168.100.76`, hôte Docker `192.168.100.89`, Authentik). Tout ce qui suit est à exécuter et valider par vous.
>
> **Légende des pastilles** : 🔵 = à exécuter sur le **DC** (PowerShell 5.1 élevé, `192.168.100.76`) · 🟢 = à exécuter sur l'**hôte Docker** (bash, `192.168.100.89`) · 🟠 = à exécuter sur un **poste client de test** domain-joined (PowerShell ou invite de commandes). Une étape sans pastille est une lecture/vérification, pas une commande à taper.
>
> **L'hôte Docker (`192.168.100.89`) n'est PAS joint au domaine AD.** Conséquences traitées dans ce runbook :
> - Aucune résolution DNS automatique vers `vaultwardensso.local` : les FQDN nécessaires sont soit résolus en interne par Docker (alias réseau `caddy`↔`vault.vaultwardensso.local`), soit forcés en statique (`/etc/hosts` local, `extra_hosts` dans `docker-compose.yml`) — jamais par un changement du résolveur DNS système (évite la fuite OPSEC de noms internes vers un résolveur public, cf. `legacy/docs/00_RETROSPECTIVE_embuches.md` piège #1).
> - `smbclient` fonctionne sans domain join (authentification NTLM explicite) mais le nom de compte est qualifié par son domaine (`'VAULTWARDENSSO\Administrator'`) pour éviter toute ambiguïté de royaume.
> - Tout ce qui est SPNEGO/Negotiate (Phase 3, Phase 4) se teste **uniquement depuis un poste 🟠 domain-joined** — jamais depuis le serveur Debian, qui n'a et n'aura pas de TGT Kerberos.

## Placeholders à substituer avant de commencer

| Placeholder | Où | Valeur réelle attendue |
|---|---|---|
| `<CLIENT_SUBNET>` | `deploy/authentik/kerberos-sso-blueprint.yaml` | CIDR du LAN intranet (ex. `192.168.100.0/24`) |
| `<AUTHENTIK_IP>` / `VW_AUTHENTIK_IP` | `deploy/firewall/vw-egress-fw.sh` **et** `.env` (`VW_AUTHENTIK_IP`) | IP réelle d'`auth.vaultwardensso.local` — même valeur aux deux endroits, hôte non domain-joined donc pas de résolution DNS AD automatique |
| `<slug>` | `.env` (`VW_SSO_AUTHORITY`), doc Authentik | slug du Provider OIDC Vaultwarden créé côté Authentik |
| `TargetOuDn` | paramètre de `Deploy-KerberosSSO-GPO.ps1` | DN de l'OU contenant les postes clients |
| Version OIDCWarden | `deploy/docker/Dockerfile` | `v2026.6.4-1` épinglée à la rédaction — **revérifier** sur `hub.docker.com/r/timshel/oidcwarden/tags` avant build |
| `<URL_DU_DEPOT_GIT>` | Phase 1.0a | URL de clone du dépôt (SSH ou HTTPS selon vos accès) |
| `<NomServeur>\<NomCA>` | Phase 1.1b (`certreq -submit -config`) | valeur constatée dans cet environnement : `SRVADTEST\vaultwardensso-srvadtest-CA` (à reconstruire depuis `certutil -ADCA` si la CA change — voir §1.1b) |

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

### 1.0a 🟢 Provisionner le dépôt sur le serveur reset

```bash
git clone <URL_DU_DEPOT_GIT> vaultwarden-stack-SSO
cd vaultwarden-stack-SSO
git checkout claude/sso-kerberos-vaultwarden-ad-rzg3w0
docker --version && docker compose version
# attendu : les deux commandes répondent (pas de "command not found")
```

### 1.0b 🟢 Si Docker n'est pas installé (à sauter sinon)

```bash
curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker.gpg] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
sudo systemctl enable --now docker
```

### 1.1 Obtenir la chaîne TLS (état réel constaté sur `C:\` du DC)

Inventaire du `C:\` du DC à ce stade (cf. capture) :

| Fichier | Statut |
|---|---|
| `adcs-root.cer`, `adcs-root.pem`, `adcs-root.b64` | Racine AD CS déjà exportée **et déjà convertie en PEM** — pas de reconversion DER→PEM nécessaire. |
| `auth-vw.csr`, `auth-vw.rsp`, `auth-vw.cer`, `auth-vw.pem` | Certificat serveur déjà demandé (`certreq -new`) et émis, mais **orphelin** : `certreq -accept` (même avec `-machine`) échoue avec `CRYPT_E_NOT_FOUND` — la machine n'a plus le binding local vers la clé privée générée pour cette CSR. Inutilisable tel quel, cf. §1.1a-b : régénération d'une CSR fraîche requise. |
| `authentik.keytab` | Déjà présent — la Phase 2 (§2.1) a déjà tourné ou le fichier a été pré-positionné ; vérifier son intégrité (§2.4) avant de le considérer acquis, ne pas relancer le script Phase 2 dessus. |
| `adfs_cert.cer`, `adfs_cert.rsp`, `adfs_req.csr`, `adfs_req.inf` | ⚠️ Artefacts de l'ancien projet AD FS (archivé dans `legacy/`) — **ne pas utiliser**, à purger en Phase 6. |
| `caddy-internal-root.crt` | ⚠️ Résidu d'un test antérieur avec `tls internal` — **ne pas utiliser**, à purger en Phase 6. |

**a. 🔵 Tenter de lier la clé privée au certificat déjà émis**

⚠️ `certreq -accept` **sans contexte explicite** cherche la requête en attente dans le magasin **utilisateur** par défaut sur ce build. Or l'INF d'origine porte `MachineKeySet = TRUE` : la clé privée pendante est dans le magasin **machine**, d'où le premier échec (`-user | -machine argument`). **Passer `-machine` explicitement** :

```powershell
certreq -accept -machine C:\auth-vw.cer
```

**Constaté en pratique : ceci échoue aussi**, avec `Cannot find object or property. 0x80092004 (CRYPT_E_NOT_FOUND)` / *A certificate issued by the certification authority cannot be installed*. Le flag `-machine` était nécessaire mais pas suffisant : ce n'est pas un problème de magasin user vs machine, c'est que **la machine n'a plus la trace de la requête en attente** correspondant à `auth-vw.cer` (le fichier `.cer` existe, mais son binding local à la clé privée générée par `certreq -new` a disparu — session différente, ou état de la machine réinitialisé entre la génération de la CSR et l'acceptation). Un `.cer` orphelin de sa requête locale ne peut pas être accepté : **passer directement à b.**

**b. 🔵 Régénérer une CSR fraîche et l'accepter dans la foulée, même session**

Nouveaux noms de fichiers (`vault-new.*`) pour ne pas mélanger avec les `auth-vw.*` orphelins :

```powershell
certutil -ADCA
```
`certutil -ADCA` **n'affiche pas** de ligne littérale `"Config:"` — la valeur pour `-config` se reconstruit à partir de deux champs de la sortie : le nom de la CA (premier `CN=` de `cACertificateDN`) et le nom de la machine CA (visible dans la liste ACL, entrée `<DOMAINE>\<NOM_MACHINE>$`). Constaté dans cet environnement : `cACertificateDN = CN=vaultwardensso-srvadtest-CA, ...` et `Allow Full Control  VAULTWARDENSSO\SRVADTEST$` → `-config "SRVADTEST\vaultwardensso-srvadtest-CA"` (déjà substitué ci-dessous).

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
"@ | Out-File -Encoding ascii vault-new.inf

certreq -new -machine vault-new.inf vault-new.csr
certreq -submit -attrib "CertificateTemplate:WebServer" -config "SRVADTEST\vaultwardensso-srvadtest-CA" vault-new.csr vault-new.cer
certreq -accept -machine vault-new.cer
```

⚠️ `-submit` **n'accepte pas** `-machine` sur ce build (`Unexpected argument: -machine` + boîte de dialogue *Certificate Request Processor: The parameter is incorrect. 0x80070057*) — le contexte machine a déjà été fixé par `-new -machine` qui crée la requête en attente dans le magasin machine ; `-submit` se contente de poster le CSR à la CA, il n'a pas besoin de connaître ce contexte. Seuls `-new` et `-accept` prennent `-machine` sur cette version de `certreq`.

Ne pas fermer la session PowerShell entre `-new` et `-accept` : c'est justement cet écart de session/état qui a rendu `auth-vw.cer` inutilisable.

**c. 🔵 Exporter la clé privée**

⚠️ **Ne pas taper le mot de passe du PFX à la main sur deux machines différentes.** Cinq échecs identiques de suite (`Mac verify error`, y compris avec `-legacy` qui charge correctement) pointent vers un mot de passe mal retranscrit entre la session PowerShell du DC et le prompt masqué du terminal Debian (clavier, encodage, copier-coller qui déforme un caractère) — pas vers un problème d'algorithme. La parade : générer le mot de passe, le vérifier **dans la même session DC** avant de quitter, et le transporter dans un fichier via le même canal `smbclient` déjà utilisé pour le PFX plutôt que de le retaper :

```powershell
$thumb = (Get-PfxCertificate -FilePath C:\vault-new.cer).Thumbprint
$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $thumb }
if (-not $cert) { throw "Certificat non trouve dans Cert:\LocalMachine\My juste apres -accept - verifier les erreurs de b ci-dessus avant de continuer" }
$pfxPassPlain = -join ((48..57)+(65..90)+(97..122) | Get-Random -Count 24 | ForEach-Object { [char]$_ })
$pfxPass = ConvertTo-SecureString -String $pfxPassPlain -AsPlainText -Force
Export-PfxCertificate -Cert $cert -FilePath C:\vault-new.pfx -Password $pfxPass
(Get-PfxCertificate -FilePath C:\vault-new.pfx -Password $pfxPass).Subject
# attendu : CN=vault.vaultwardensso.local -- si ca erreur ici, le probleme est dans l'export, pas le transfert
Set-Content -Path C:\vault-new.pfxpass.txt -Value $pfxPassPlain -NoNewline -Encoding ascii
```

**d. 🟢 Transférer, y compris le fichier mot de passe**

```bash
smbclient //192.168.100.76/C$ -U 'VAULTWARDENSSO\Administrator' -c 'get vault-new.pfx; get vault-new.pfxpass.txt; get vault-new.cer; get adcs-root.pem'
file vault-new.cer   # verifier le format reel avant conversion
openssl x509 -in vault-new.cer -out vault-new.pem
```
⚠️ `certreq -submit` **sans `-binary`** sort le certificat encodé en Base64 (compatible PEM), pas en DER brut : `-inform der` échoue avec `No supported data to decode` sur ce fichier. `openssl x509` sans `-inform` explicite attend du PEM par défaut, ce qui correspond au format réel produit ici — pas de conversion DER→PEM nécessaire.

**e. 🟢 Vérifier ce que couvre réellement le certificat avant de le monter**

```bash
openssl x509 -in vault-new.pem -noout -subject -ext subjectAltName
# attendu : vault.vaultwardensso.local present dans le SAN
```

Si `vault.vaultwardensso.local` n'apparaît pas dans le SAN, **STOP** — ce n'est pas le bon certificat pour Caddy, ne pas continuer avec celui-ci.

**f. 🟢 Convertir et assembler la chaîne** — mot de passe lu depuis le fichier transféré, jamais retapé

⚠️ `Export-PfxCertificate` sur ce DC **Windows Server 2016** chiffre le PFX en 3DES/SHA1 (legacy) ; OpenSSL 3.x (Debian 13) désactive ces algorithmes par défaut et exige `-legacy` pour même tenter le déchiffrement :

```bash
openssl pkcs12 -legacy -in vault-new.pfx -nocerts -nodes -out vault.key -passin file:vault-new.pfxpass.txt
```

Si `-legacy` renvoie `unknown option` ou `provider "legacy" not found` (module absent du paquet openssl) :

```bash
openssl pkcs12 -provider legacy -provider default -in vault-new.pfx -nocerts -nodes -out vault.key -passin file:vault-new.pfxpass.txt
```

Si ça échoue encore avec `Mac verify error` alors que §1.1c a confirmé que le PFX s'ouvre bien sur le DC avec le même mot de passe : le fichier a probablement été corrompu pendant le transfert — comparer un hash des deux côtés (`sha256sum vault-new.pfx` côté Debian vs `Get-FileHash C:\vault-new.pfx` côté DC) et retransférer si besoin, plutôt que de re-suspecter le mot de passe.

```bash
cat vault-new.pem adcs-root.pem > vault.crt
openssl x509 -in adcs-root.pem -noout -fingerprint -sha1
# attendu : 473BAAC9189D52715E3E73CED9BEC691293BED10 (comparer à la valeur de contexte)
```

**g. Purger les fichiers transitoires** (le PFX et le fichier mot de passe sont des secrets ; `auth-vw.*` orphelins peuvent aussi être purgés)

🔵 :
```powershell
Remove-Item C:\vault-new.pfx, C:\vault-new.pfxpass.txt -Force
Remove-Item C:\auth-vw.cer, C:\auth-vw.csr, C:\auth-vw.rsp, C:\auth-vw.pem -Force -ErrorAction SilentlyContinue   # orphelins, plus utilisables
```

🟢 :
```bash
rm -f vault-new.pfx vault-new.pfxpass.txt
```

### 1.2 🟢 Placer les fichiers dans le dépôt

```bash
cd vaultwarden-stack-SSO
sudo install -o root -g root -m 644 vault.crt  deploy/caddy/certs/vault.crt
sudo install -o root -g root -m 600 vault.key  deploy/caddy/certs/vault.key
sudo install -o root -g root -m 644 adcs-root.pem deploy/docker/adcs-root.crt
rm -f vault.crt vault.key vault-new.pfx vault-new.cer vault-new.pem adcs-root.pem   # copies locales transitoires
```

### 1.3 🟢 Secrets applicatifs

```bash
cd deploy/docker
cp .env.example .env
chmod 600 .env
openssl rand -base64 48   # coller le résultat dans .env -> VW_ADMIN_TOKEN=...
nano .env                 # (ou vi/vim) renseigner VW_ADMIN_TOKEN
```

### 1.4 🟢 Déploiement

```bash
cd deploy/docker
mkdir -p vw-data caddy/logs   # bind mounts attendus par docker-compose.yml, absents sur un serveur reset
docker compose up -d caddy
```

### 1.5 🟢 Résolution locale pour les gates (hôte non domain-joined)

Le shell Debian n'a pas de DNS lui donnant `vault.vaultwardensso.local` (le host n'est pas membre du domaine). Sans entrée statique, `openssl s_client -connect vault.vaultwardensso.local:443` échoue à résoudre alors même que Caddy écoute bien sur cette machine :

```bash
echo "127.0.0.1 vault.vaultwardensso.local" | sudo tee -a /etc/hosts
```

### 1.6 🟢 Gate

```bash
openssl s_client -connect vault.vaultwardensso.local:443 -servername vault.vaultwardensso.local </dev/null 2>/dev/null | openssl x509 -noout -issuer
# attendu : issuer = CA AD CS (thumbprint 473B...)

openssl s_client -connect vault.vaultwardensso.local:443 -servername vault.vaultwardensso.local -CAfile deploy/docker/adcs-root.crt </dev/null 2>&1 | grep "Verify return code"
# attendu : Verify return code: 0 (ok)
```

### 1.7 🟢 Dette immédiate à solder (confiance TLS du conteneur)

Le conteneur `vaultwarden` résout `vault.vaultwardensso.local` en interne via l'alias réseau Docker posé sur `caddy` (`deploy/docker/docker-compose.yml`, réseau `backend`) — **pas** besoin de DNS ni de `/etc/hosts` côté conteneur, ça fonctionne même hôte non domain-joined :

```bash
docker compose up -d --build vaultwarden
docker exec vaultwarden curl -fsS https://vault.vaultwardensso.local/alive
# attendu : réponse JSON, pas d'erreur "unable to get local issuer certificate"
```

---

## Phase 2 — Compte de service + SPN + keytab (DC)

**Fichier** : `deploy/kerberos/Setup-KerberosSPNEGO-DC.ps1`

> **État constaté** : `C:\authentik.keytab` existe déjà sur le DC (cf. capture) — soit le script a déjà tourné, soit le fichier a été pré-positionné. 🔵 Vérifier avant de relancer quoi que ce soit :
> ```powershell
> Get-ADUser -Filter "SamAccountName -eq 'svc-authentik-krb'" -ErrorAction SilentlyContinue
> ```
> - **Compte présent** : le script s'arrêtera de lui-même si relancé (garde anti-doublon, §2.1 du script) — ne pas insister, passer directement au transfert (§2.4) après avoir vérifié l'intégrité du keytab.
> - **Compte absent** (keytab orphelin d'un essai précédent) : supprimer `C:\authentik.keytab` avant de lancer le script, pour repartir sur un état propre et cohérent (le script refuse d'écraser un fichier existant, §6 du script).

### 2.1 🔵 Exécution du script (à sauter si le compte existe déjà, cf. ci-dessus)

```powershell
cd C:\vaultwarden-stack-SSO\deploy\kerberos
.\Setup-KerberosSPNEGO-DC.ps1 -SpnHostname 'auth.vaultwardensso.local' -Realm 'VAULTWARDENSSO.LOCAL' -Domain 'VAULTWARDENSSO'
```

Gates intégrés au script (STOP automatique si échec) : anti-doublon SPN, `msDS-SupportedEncryptionTypes = 24` confirmé, SPN confirmé après `setspn -S`, code de sortie `ktpass` vérifié, kvno affiché, SHA-256 du keytab affiché.

### 2.2 🖱️ Refus de logon interactif (GPO) — pas de commande fiable, action GUI requise

Il n'existe pas de cmdlet dans le module `GroupPolicy` pour les *User Rights Assignments* (`SeDenyInteractiveLogonRight`/`SeDenyRemoteInteractiveLogonRight`) : ce sont des réglages de sécurité (`GptTmpl.inf`) dont l'édition brute en SYSVOL est fragile (désynchronisation possible entre le `Version` de `gpt.ini` et l'attribut `versionNumber` de l'objet GPO en AD, qui provoque une non-application silencieuse). Microsoft recommande la console GPMC (ou l'outil externe `LGPO.exe`). Procédure GUI (sur le DC) :

1. `gpmc.msc` → clic droit sur l'OU cible → *Create a GPO in this domain, and Link it here* → nommer `Deny-Interactive-SvcAccounts`.
2. Éditer la GPO → *Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → User Rights Assignment*.
3. *Deny log on locally* → Add User or Group → `GG-SvcAccounts-DenyInteractiveLogon` (groupe créé par le script Phase 2.1).
4. *Deny log on through Remote Desktop Services* → même groupe.

### 2.3 🔵 Gate

```powershell
gpupdate /force
```
Gate réel : `klist` côté DC n'est **pas** suffisant — la validation réelle se fait Phase 3.

### 2.4 🟢 Transfert du keytab

```bash
smbclient //192.168.100.76/C$ -U 'VAULTWARDENSSO\Administrator' -c 'get authentik.keytab'
sha256sum authentik.keytab
# comparer avec le hash affiché par le script côté DC (Get-FileHash) -> DOIT être identique
sudo chown root:root authentik.keytab
sudo chmod 600 authentik.keytab
```

Puis supprimer le fichier source du DC une fois l'intégrité confirmée :

```bash
smbclient //192.168.100.76/C$ -U 'VAULTWARDENSSO\Administrator' -c 'del authentik.keytab'
```

---

## Phase 3 — Source Kerberos Authentik

**Fichiers** : `deploy/authentik/kerberos-sso-blueprint.yaml`, `deploy/authentik/README.md`

### 3.1 🟢 Substitution du placeholder

```bash
sed -i 's#<CLIENT_SUBNET>#192.168.100.0/24#' deploy/authentik/kerberos-sso-blueprint.yaml
```

### 3.2 🟢 Import du blueprint

```bash
docker exec -i authentik-server ak import_blueprint < deploy/authentik/kerberos-sso-blueprint.yaml
```
*(adapter le nom du conteneur/serveur Authentik réel — sinon 🖱️ import via Admin → System → Blueprints → Import)*

### 3.3 🖱️ Upload du keytab — action GUI (secret, jamais scriptable vers un tiers)

🟢 :
```bash
base64 -w0 authentik.keytab > authentik.keytab.b64
```
🖱️ Coller le contenu de `authentik.keytab.b64` dans Directory → Federation & Social login → *Kerberos SPNEGO SSO* → champ Keytab (GUI Authentik). Puis :

🟢 :
```bash
shred -u authentik.keytab.b64
```

### 3.4 🖱️ Vérification (GUI) des champs de la source

Confirmer dans l'UI : `spnego_server_name = HTTP/auth.vaultwardensso.local`, `user_matching_mode = username_deny`, `sync_users = false`.

### 3.5 Gates séquentiels

🟠 a. :
```bash
curl --negotiate -u : https://auth.vaultwardensso.local/source/kerberos/kerberos-sso/login/
# attendu : 302 (pas 401 final)
```

🖱️ b. Navigateur poste domaine → `https://vault.vaultwardensso.local` → aucun formulaire affiché.
🖱️ c. Poste hors domaine → formulaire password affiché (fallback).
🖱️ d. Admin Authentik → Events → un `login` source `kerberos-sso`, sans stage password traversé.

---

## Phase 4 — GPO postes clients

**Fichiers** : `deploy/gpo/Deploy-KerberosSSO-GPO.ps1`, `deploy/gpo/firefox-policies.json`, `deploy/gpo/Deploy-BitwardenClients.reg`

### 4.1 🔵 GPO navigateurs (zone Intranet, AuthServerAllowlist, extension Bitwarden)

```powershell
cd C:\vaultwarden-stack-SSO\deploy\gpo
.\Deploy-KerberosSSO-GPO.ps1 -TargetOuDn 'OU=Postes,DC=vaultwardensso,DC=local' -AuthHostname 'auth.vaultwardensso.local' -VaultBaseUrl 'https://vault.vaultwardensso.local'
```

### 4.2 🟠 Alternative manuelle poste-par-poste (utile pour le test isolé, évite d'attendre un cycle de réplication GPO)

```powershell
reg import \\192.168.100.76\C$\vaultwarden-stack-SSO\deploy\gpo\Deploy-BitwardenClients.reg
```

### 4.3 Firefox — network.negotiate-auth.trusted-uris (déploiement sur le poste de test)

🔵 :
```powershell
New-Item -ItemType Directory -Force -Path '\\vaultwardensso.local\SYSVOL\vaultwardensso.local\scripts' | Out-Null
Copy-Item -Path C:\vaultwarden-stack-SSO\deploy\gpo\firefox-policies.json -Destination '\\vaultwardensso.local\SYSVOL\vaultwardensso.local\scripts\firefox-policies.json' -Force
```
🟠 :
```powershell
New-Item -ItemType Directory -Force -Path 'C:\Program Files\Mozilla Firefox\distribution' | Out-Null
Copy-Item -Path '\\vaultwardensso.local\SYSVOL\vaultwardensso.local\scripts\firefox-policies.json' -Destination 'C:\Program Files\Mozilla Firefox\distribution\policies.json' -Force
```
Pour un déploiement fleet (pas juste le poste de test), convertir cette copie en GPO Files preference (🖱️ GPMC → User/Computer Configuration → Preferences → Windows Settings → Files) ou en script de démarrage GPO — hors périmètre d'un runbook d'évaluation à un seul poste.

### 4.4 🟠 Gate

```powershell
gpupdate /force
gpresult /r
```
🖱️ DevTools navigateur → en-tête `Authorization: Negotiate` sur la requête vers `auth.vaultwardensso.local`.
🖱️ Firefox : `about:policies` → `NegotiateAuth.Trusted` doit lister l'URL Authentik.

---

## Phase 5 — Bascule OIDCWarden + TDE

**Fichiers** : `deploy/docker/Dockerfile`, `deploy/docker/docker-compose.yml`, `deploy/docker/.env.example`, `deploy/firewall/vw-egress-fw.sh`, `deploy/systemd/vw-egress-fw.service`, `docs/02_risk_analysis_tde.md`

### 5.1 🟢 Backup préalable

La stack (`docker-compose.yml`) n'a pas de `DATABASE_URL` défini : backend **SQLite** par défaut (`vw-data/db.sqlite3`) — un backup fichier suffit (adapter si vous avez configuré Postgres/MySQL en plus) :

```bash
cd deploy/docker
tar czf ../../backup-vw-data-$(date +%Y%m%d-%H%M%S).tar.gz vw-data/
```

Gate — restauration testée à blanc :

```bash
mkdir -p /tmp/restore-test
tar xzf backup-vw-data-*.tar.gz -C /tmp/restore-test
sqlite3 /tmp/restore-test/vw-data/db.sqlite3 "PRAGMA integrity_check;"
# attendu : ok
rm -rf /tmp/restore-test
```

### 5.2 🟢 Firewall egress + résolution Authentik (hôte non domain-joined : IP statique requise aux deux endroits)

`<AUTHENTIK_IP_REELLE>` doit être la **même valeur** dans `vw-egress-fw.sh` (règle iptables) et dans `.env` (`VW_AUTHENTIK_IP`, utilisé par `extra_hosts` dans `docker-compose.yml`) :

```bash
sed -i 's/__AUTHENTIK_IP__/<AUTHENTIK_IP_REELLE>/' deploy/firewall/vw-egress-fw.sh
sudo cp deploy/firewall/vw-egress-fw.sh /usr/local/sbin/
sudo chmod 700 /usr/local/sbin/vw-egress-fw.sh
sudo cp deploy/systemd/vw-egress-fw.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vw-egress-fw.service
sudo iptables -L DOCKER-USER -n -v --line-numbers   # gate visuel
```

### 5.3 🟢 Compléter .env (Phase 5)

```bash
nano deploy/docker/.env
# renseigner VW_SSO_CLIENT_ID, VW_SSO_CLIENT_SECRET, VW_SSO_AUTHORITY, VW_AUTHENTIK_IP
# (VW_SSO_AUTHORITY = coller VERBATIM l'issuer depuis
#  https://auth.vaultwardensso.local/application/o/<slug>/.well-known/openid-configuration)
# (VW_AUTHENTIK_IP = meme IP que <AUTHENTIK_IP_REELLE> ci-dessus - hote non domain-joined,
#  pas de DNS AD automatique pour resoudre auth.vaultwardensso.local depuis le conteneur)
```

### 5.4 🟢 Build et déploiement

```bash
cd deploy/docker
docker compose build
docker compose up -d
docker compose logs -f vaultwarden   # surveiller le démarrage / erreurs SSO_AUTHORITY
```

### 5.5 🖱️ Organization + policies TDE — action GUI (admin OIDCWarden `/admin`)

1. Créer l'Organization cible.
2. Activer policy **Single Organization**.
3. Activer policy **Account Recovery Administration** (auto-enrollment).
4. Mapper le groupe AD (claims groupes Authentik → `SSO_ORGANIZATIONS_*`) pour invitation automatique.

### 5.6 🖱️ Compte break-glass — action GUI, AVANT SSO_ONLY=true

Créer un compte local (email hors domaine dédié), master password fort généré hors ligne et scellé physiquement, **exclu de l'Organization SSO**.

### 5.7 🖱️ Gates (manuels, navigateur)

Login SSO compte test → flux complet sans régression → visible `/admin`.
Gate TDE : onboarding → device approval → login N+2 → aucun master password demandé.
Gate break-glass : login réussi même après passage à `SSO_ONLY=true`.

### 5.8 🟢 Bascule SSO_ONLY (uniquement après 5.7 validé)

```bash
sed -i 's/SSO_ONLY: "false"/SSO_ONLY: "true"/' deploy/docker/docker-compose.yml
docker compose up -d vaultwarden
```

---

## Phase 6 — Hygiène, supervision

**Fichier** : `docs/03_supervision_siem.md`

🟢 :
```bash
shred -u backup-vw-data-*.tar.gz   # si conservé le temps du test uniquement, sinon archiver en lieu sûr
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

1. Une commande à la fois, sortie attendue annoncée, valider avant la suivante.
2. Tout écart entre sortie observée et attendue = STOP + diagnostic, pas de contournement.
3. Aucun secret dans les réponses, les logs, ou les fichiers versionnés — placeholders systématiques.
4. Versions épinglées partout (Dockerfile OIDCWarden) — revérifier avant chaque build.
5. Les étapes marquées 🖱️ sont GUI par nature (secret binaire, wizard, ou réglage sans cmdlet fiable) — ce n'est pas un oubli, c'est documenté comme tel plutôt que remplacé par une commande fragile.
6. Les pastilles 🔵/🟢/🟠 remplacent les préfixes `DC>`/`DEBIAN>`/`POSTE-TEST>` sur chaque commande : une commande dans un bloc sous une pastille se tape telle quelle, sans préfixe, sur la machine indiquée.
