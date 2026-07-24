# Runbook d'installation — SSO Kerberos passwordless (Phases 0 à 6)

> **Usage** : version consolidée pour un déploiement complet en un minimum de passages, en repartant de zéro (DC et hôte Docker), sur **votre propre infrastructure**. Les commandes de chaque bloc se collent d'une traite sur la machine indiquée. Les **gates** restent des points d'arrêt : vérifier la sortie attendue avant de passer au bloc suivant — un gate qui échoue = diagnostiquer, pas contourner.
>
> **Aucune valeur de ce runbook n'est figée à un site particulier.** Toutes les commandes utilisent les variables définies une seule fois en Phase 0 (`deploy/environment.env`) — realm AD, hostnames, IP du DC, reseaux clients (VLAN)... Rien de ce dépôt ne doit contenir de valeur en dur spécifique à votre AD ; si vous en trouvez une hors de cette Phase 0, signalez/corrigez-la.
>
> **Ce que ce dépôt ne peut pas faire à votre place** : aucune commande de ce runbook n'a été exécutée contre votre infrastructure réelle. Tout ce qui suit est à exécuter et valider par vous.
>
> **Légende des pastilles** : 🔵 = à exécuter sur le **DC** (PowerShell 5.1 élevé) · 🟢 = à exécuter sur l'**hôte Docker** (bash — Debian/Ubuntu supposé pour l'auto-installation de paquets ; sur une autre distribution, installer git/docker/smbclient/openssl manuellement puis relancer) · 🟠 = à exécuter sur un **poste client de test** domain-joined (PowerShell ou invite de commandes). Une étape sans pastille est une lecture/vérification, pas une commande à taper.
>
> **Hypothèse réseau** : l'hôte Docker n'est **pas** joint au domaine AD (aucune résolution DNS automatique vers votre zone AD). **Authentik tourne sur cette même VM** que Vaultwarden/Caddy (server + worker + PostgreSQL + Redis, même `docker-compose.yml`) : pas d'IP LAN ni de règle firewall dédiée à connaître, Caddy rejoint Authentik par nom de service Docker. **Tout passe par Caddy** : `VAULT_HOSTNAME` et `AUTH_HOSTNAME` sont tous les deux résolus en interne par Docker vers le conteneur Caddy. Tout ce qui est SPNEGO/Negotiate (Phase 3, Phase 4) se teste **uniquement depuis un poste 🟠 domain-joined**, jamais depuis l'hôte Docker.
>
> **Plusieurs réseaux/VLAN clients** : la redirection Kerberos automatique (Phase 3) accepte une **liste** de CIDR (`CLIENT_SUBNETS`, séparés par des virgules) — LAN filaire, WiFi corporate, VPN site-to-site, autre site AD, etc. peuvent coexister sans configuration supplémentaire. Un client hors de toutes ces plages n'est jamais bloqué : il voit simplement le formulaire mot de passe classique (fallback), jamais une erreur.

## Pré-requis côté Active Directory (à valider AVANT la Phase 0)

Rien de ce qui suit n'est automatisé par ce dépôt — ce sont des conditions d'existence de votre AD, pas des étapes que les scripts peuvent créer à votre place. Un seul manquant bloque une phase précise, indiquée entre parenthèses.

**Infrastructure et rôles**
- [ ] Domaine AD DS existant, niveau fonctionnel **Windows Server 2008 ou supérieur** (nécessaire pour l'attribut `msDS-SupportedEncryptionTypes` — AES only, Phase 2). Tout domaine à jour aujourd'hui satisfait ce prérequis, mais un domaine legacy peut ne pas l'avoir.
- [ ] **AD CS (Certificate Services)** — Autorité de certification Enterprise (racine ou subordonnée) installée et opérationnelle sur le domaine. Sans AD CS, toute la Phase 1 (TLS) est à refaire avec une PKI tierce (hors périmètre de ce dépôt).
- [ ] Gabarit de certificat **`WebServer`** (ou équivalent renseigné dans `CERT_TEMPLATE`) publié sur la CA et **enrollable** par le compte qui exécutera `New-VaultCertDC.ps1` (droit *Enroll*, cf. Security tab du gabarit dans `certtmpl.msc`) — Phase 1.
- [ ] Gabarit **`Domain Controller Authentication`** (ou équivalent) auto-enrollé ou émis manuellement sur le(s) DC utilisé(s) pour LDAPS — sans certificat Schannel valide sur le port 636, la Source LDAP (Phase 2bis) ne pourra jamais se connecter en `ldaps://`. Vérifiable via `certlm.msc` (magasin Personal du DC) ou le gate `openssl s_client -connect <DC_IP>:636`.

**Découverte de `CA_CONFIG` et `CA_ROOT_THUMBPRINT`** (à faire AVANT de remplir `deploy/environment.env`, Phase 0 — aucun script de ce dépôt ne les découvre à votre place, `New-VaultCertDC.ps1` se contente de les consommer) :

```powershell
# 🔵 DC (ou tout poste avec les RSAT AD CS Tools)
certutil -ADCA
```

Une seule commande suffit dans le cas le plus courant (CA Enterprise **racine**, celui par défaut de ce dépôt) — repérer ces champs précis dans la sortie :

| Champ affiché par `certutil -ADCA` | Variable `environment.env` | Comment le lire |
|---|---|---|
| `dNSHostName = <machine>.<domaine>` (partie avant le premier point) + `cn = <nom-CA>` | `CA_CONFIG` | Concaténer `<machine>\<nom-CA>` — ex. `dNSHostName = SRVADTEST.vaultwardensso.local` et `cn = vaultwardensso-SRVADTEST-CA` → `CA_CONFIG=SRVADTEST\vaultwardensso-SRVADTEST-CA` |
| `Cert Hash(sha1): xx xx xx ...` | `CA_ROOT_THUMBPRINT` | Supprimer les espaces, mettre en majuscules — ex. `21 a0 63 c1 06 fe 3b 68 c5 49 9b 27 98 b0 4a 10 f5 58 b9 ea` → `CA_ROOT_THUMBPRINT=21A063C106FE3B68C5499B2798B04A10F558B9EA` |

**Condition pour que `Cert Hash(sha1)` soit directement la bonne valeur** : la ligne `Root Certificate: Subject matches Issuer` doit être présente juste au-dessus — elle confirme que cette CA est bien auto-signée (root), donc que son propre hash EST le thumbprint de la racine. Si cette ligne indique un mismatch (CA subordonnée), le hash affiché ici n'est pas le bon : remonter jusqu'à la vraie racine avec `Get-ChildItem Cert:\LocalMachine\Root | Select-Object Subject, Thumbprint | Format-List` et repérer celle dont le Subject correspond à votre chaîne de confiance.

Pas de ligne littérale `"Config:"` dans la sortie de `certutil -ADCA` — c'est la reconstruction `<machine CA>\<nom CA>` ci-dessus qu'il faut faire à la main. La racine doit déjà être présente dans `Cert:\LocalMachine\Root` sur un DC/poste joint au domaine (autoenrollment de la CA Enterprise) ; si elle n'y est pas, publier la racine via GPO (Computer Configuration → Policies → Windows Settings → Security Settings → Public Key Policies → Trusted Root Certification Authorities) avant de continuer.

**Outils requis sur le DC (ou le poste d'administration RSAT)**
- [ ] Module PowerShell **`ActiveDirectory`** (RSAT-AD-PowerShell) — `Setup-KerberosSPNEGO-DC.ps1` et `Setup-LDAPBind-DC.ps1` en dépendent explicitement (`#Requires -Modules ActiveDirectory`).
- [ ] Module PowerShell **`GroupPolicy`** + console **GPMC** — `Deploy-KerberosSSO-GPO.ps1` en dépend (`#Requires -Modules GroupPolicy`), et la GPMC GUI reste nécessaire pour l'étape manuelle de refus de logon interactif (Phase 2, User Rights Assignment — pas de cmdlet fiable pour ça).
- [ ] `ktpass.exe` et `setspn.exe` disponibles (natifs sur un DC ; sur un membre du domaine, installer les RSAT AD DS Tools) — Phase 2, génération du keytab.

**Permissions du compte d'exécution (sur le DC)**
- [ ] Droits suffisants pour : créer des OU (`New-ADOrganizationalUnit`), créer des comptes utilisateurs et groupes de sécurité (`New-ADUser`/`New-ADGroup`), modifier `msDS-SupportedEncryptionTypes` et réinitialiser un mot de passe de compte de service (ce que fait `ktpass`), écrire un SPN (`setspn -S`) — en pratique Domain Admin, ou une délégation équivalente sur l'OU cible si vous voulez éviter ce niveau de privilège.
- [ ] Droits de création/liaison de GPO (membre de *Group Policy Creator Owners* ou Domain Admins) **et** droit d'édition sur l'OU liée (`GPO_TARGET_OU_DN`) — Phase 4.
- [ ] Administrateur local sur le DC lui-même (les scripts écrivent des fichiers sensibles en `C:\`, ex. keytab, mot de passe de bind LDAP) — toutes phases DC.

**Structure AD à avoir déjà, ou à créer manuellement**
- [ ] Une **OU pour les postes clients** doit déjà exister et son DN complet être renseigné dans `GPO_TARGET_OU_DN` (`deploy/environment.env`) — ce dépôt ne la crée jamais, seule l'OU de synchronisation LDAP (`LDAP_SYNC_OU_NAME`, défaut `Vaultwarden` — un simple nom, pas un DN, créée automatiquement si absente) est gérée par `Setup-LDAPBind-DC.ps1`. Découverte :
  ```powershell
  # 🔵 DC
  Get-ADOrganizationalUnit -Filter * | Select-Object Name, DistinguishedName
  ```
  Copier tel quel le `DistinguishedName` de l'OU contenant vos postes → `GPO_TARGET_OU_DN`. Exemple : domaine `vaultwardensso.local`, OU `Postes` à la racine → `OU=Postes,DC=vaultwardensso,DC=local` ; imbriquée sous un site `Paris` → `OU=Postes,OU=Paris,DC=vaultwardensso,DC=local`.
- [ ] Les comptes utilisateurs à faire passer en SSO doivent être **déplacés/créés** dans l'OU de synchronisation LDAP (`LDAP_SYNC_OU_NAME`) — aucune automatisation de peuplement n'est fournie (délibéré : le choix des comptes concernés est une décision métier, pas technique).

**Réseau et résolution de noms**
- [ ] Enregistrements **DNS A** pour `VAULT_HOSTNAME` et `AUTH_HOSTNAME` créés dans la zone DNS intégrée à l'AD (ou tout DNS que vos postes clients interrogent), pointant vers l'IP de l'hôte Docker — sans ça, seul le poste sur lequel vous avez édité `hosts` manuellement pourra résoudre ces noms (le `/etc/hosts` de la Phase 1 ne couvre que l'hôte Docker lui-même, jamais les clients).
- [ ] **Synchronisation horaire** (NTP) entre le DC, l'hôte Docker et les postes clients — Kerberos refuse tout ticket hors d'une fenêtre de tolérance (5 minutes par défaut) ; un décalage d'horloge produit des échecs SPNEGO qui ressemblent à tort à un problème de config plutôt qu'à un problème de temps.
- [ ] Port **636 (LDAPS)** et le port utilisé pour Kerberos/SPNEGO (443 via Caddy pour le SPNEGO applicatif, le KDC lui-même reste sur ses ports standards 88/464 côté DC) joignables entre l'hôte Docker et le DC.

---

## Checklist globale

- [ ] Pré-requis AD validés (voir section ci-dessus)
- [ ] Phase 0 — Configuration centrale (`deploy/environment.env`)
- [ ] Phase 1 — TLS Caddy
- [ ] Phase 2 — Compte de service + SPN + keytab (DC)
- [ ] Phase 2bis — Source LDAP (provisioning des comptes)
- [ ] Phase 3 — Source Kerberos Authentik
- [ ] Phase 4 — GPO postes clients
- [ ] Phase 5 — Bascule OIDCWarden + TDE
- [ ] Phase 6 — Hygiène et supervision

---

## Phase 0 — Configuration centrale

**Fichier** : `deploy/environment.env` (copie remplie de `deploy/00_environment.env.example`)

Cette phase n'existe que sur l'hôte Docker (où vit le dépôt cloné) mais ses valeurs sont utilisées **des deux côtés** (DC et Debian) — sur le DC, `. .\deploy\00_Set-Environment.ps1` les charge dans la session PowerShell depuis une copie du même fichier.

### 🟢 DEBIAN

```bash
git clone <URL_DU_DEPOT_GIT> vaultwarden-stack-SSO
cd vaultwarden-stack-SSO
git checkout claude/sso-kerberos-vaultwarden-ad-rzg3w0

cp deploy/00_environment.env.example deploy/environment.env
nano deploy/environment.env
# Renseigner au minimum : REALM, DOMAIN_DNS, DOMAIN_NETBIOS, DC_IP,
# VAULT_HOSTNAME, AUTH_HOSTNAME, CLIENT_SUBNETS, CA_CONFIG et
# CA_ROOT_THUMBPRINT (voir "Decouverte de CA_CONFIG et CA_ROOT_THUMBPRINT"
# dans la section Pre-requis AD ci-dessus si vous ne les avez pas encore),
# GPO_TARGET_OU_DN.
```

### 🔵 DC

**Le dépôt doit exister sur le DC** (`C:\vaultwarden-stack-SSO`) — tous les scripts `deploy\...` des phases suivantes s'y exécutent. Cloner directement si Git est disponible sur le DC :

```powershell
git clone <URL_DU_DEPOT_GIT> C:\vaultwarden-stack-SSO
git -C C:\vaultwarden-stack-SSO checkout claude/sso-kerberos-vaultwarden-ad-rzg3w0
```

Si Git n'est pas installé sur le DC : télécharger une archive ZIP du dépôt (page du dépôt → Code → Download ZIP) et l'extraire dans `C:\vaultwarden-stack-SSO`, ou le transférer depuis l'hôte Docker via `smbclient` (même mécanique que ci-dessous pour `environment.env`, sur tout le dossier).

**Transférer `deploy/environment.env`** (rempli côté Debian dans le bloc précédent — ce fichier ne contient aucun mot de passe, n'importe quel canal convient) :

```bash
# 🟢 Debian -- meme mecanique que le transfert du keytab (Phase 2), en sens inverse (put, pas get).
# ${DOMAIN_NETBIOS} et ${DC_IP} = valeurs de deploy/environment.env.
smbclient "//$DC_IP/C\$" -U "${DOMAIN_NETBIOS}\\Administrator" -c 'put deploy/environment.env vaultwarden-stack-SSO/deploy/environment.env'
```

Dépose le fichier exactement à `C:\vaultwarden-stack-SSO\deploy\environment.env`, à côté de `00_Set-Environment.ps1` — son emplacement par défaut, pas besoin de `-Path` ensuite. Alternative manuelle (le fichier n'étant pas un secret, une session RDP + `notepad` + coller le contenu suffit tout aussi bien) si `smbclient` pose problème.

Puis, **avant chaque script PowerShell de ce runbook** :

```powershell
cd C:\vaultwarden-stack-SSO
. .\deploy\00_Set-Environment.ps1
# ou, si le fichier a ete depose ailleurs qu'a l'emplacement par defaut :
. .\deploy\00_Set-Environment.ps1 -Path 'C:\chemin\vers\environment.env'
```

Le point (`.`) avant le chemin est obligatoire (dot-source) : sans lui, les variables ne survivent pas au retour du script. Tous les scripts PowerShell des phases suivantes lisent alors leurs paramètres par défaut (`$env:REALM`, `$env:DC_IP`, `$env:AUTH_HOSTNAME`, etc.) — plus besoin de les retaper sur chaque commande.

### Gate

```powershell
# 🔵
$env:REALM; $env:DC_IP; $env:AUTH_HOSTNAME; $env:VAULT_HOSTNAME
# attendu : vos valeurs, pas les placeholders CHANGE_ME/EXAMPLE.LOCAL
```

---

## Phase 1 — TLS Caddy (chaîne PKI interne)

**Fichiers** : `deploy/02_caddy/Caddyfile`, `deploy/03_docker/docker-compose.yml`, `deploy/03_docker/Dockerfile`, `deploy/01_tls/New-VaultCertDC.ps1`, `deploy/01_tls/install-vault-cert.sh`

**Hypothèse** : DC et hôte Docker repartent de zéro — aucun certificat existant.

> **Raccourci scripté (recommandé)** : `New-VaultCertDC.ps1` (🔵 DC) et `install-vault-cert.sh` (🟢 Debian) automatisent l'intégralité de cette phase — idempotents, avec retries réseau, gates intégrés, et lecture automatique de `deploy/environment.env`. install-vault-cert.sh installe aussi ses propres prérequis (clone du dépôt, Docker, smbclient, openssl) s'ils manquent.
> ```powershell
> # 🔵 DC (apres Phase 0 : . .\deploy\00_Set-Environment.ps1)
> cd C:\vaultwarden-stack-SSO\deploy\01_tls
> .\New-VaultCertDC.ps1
> ```
> ```bash
> # 🟢 Debian -- si le depot n'est pas encore cloné, ajouter REPO_URL=<url_du_depot> devant.
> # Credentials SMB interactifs par defaut, ou SMB_PASSWORD=... pour un usage non interactif.
> ./deploy/01_tls/install-vault-cert.sh
> # ou, sur un serveur vierge, en une commande (copier d'abord ce fichier sur le serveur) :
> # REPO_URL=<url_du_depot> ./install-vault-cert.sh
> ```
> `install-vault-cert.sh` source automatiquement `deploy/environment.env` s'il est présent (Phase 0) : `DC_IP`, `AUTH_HOSTNAME`, `VAULT_HOSTNAME` (→ `SPN_HOSTNAME`), `CA_ROOT_THUMBPRINT` (→ `ROOT_THUMBPRINT`) et `DOMAIN_NETBIOS` (→ `DC_USER`) en sont tous issus ; il échoue tôt et clairement si l'un manque.

Les blocs manuels ci-dessous restent la référence si un script échoue et qu'il faut diagnostiquer étape par étape — remplacer `$SpnHostname`/`$AuthHostname`/`$CaConfig` par vos propres valeurs (celles de `deploy/environment.env`).

### 🔵 DC — bloc 1 : générer la CSR, l'accepter, exporter clé + racine

Tout dans **la même session PowerShell élevée, sans interruption** (un écart de session entre `-new` et `-accept` rend le certificat orphelin). Le certificat porte deux SAN (`VAULT_HOSTNAME` et `AUTH_HOSTNAME`) : **tout passe par Caddy**, y compris `AUTH_HOSTNAME` (Caddy reverse-proxie vers le vrai Authentik) — un seul certificat suffit pour les deux vhosts.

```powershell
# apres . .\deploy\00_Set-Environment.ps1
$SpnHostname  = $env:VAULT_HOSTNAME
$AuthHostname = $env:AUTH_HOSTNAME
$CaConfig     = $env:CA_CONFIG        # "<machine CA>\<nom CA>", ex: SRVDC\ExampleCA

@"
[Version]
Signature="`$Windows NT`$"
[NewRequest]
Subject = "CN=$SpnHostname"
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
_continue_ = "dns=$SpnHostname&"
_continue_ = "dns=$AuthHostname&"
"@ | Out-File -Encoding ascii vault-new.inf

certreq -new -machine vault-new.inf vault-new.csr
certreq -submit -attrib "CertificateTemplate:WebServer" -config $CaConfig vault-new.csr vault-new.cer
certreq -accept -machine vault-new.cer

$thumb = (Get-PfxCertificate -FilePath C:\vault-new.cer).Thumbprint
$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $thumb } | Select-Object -First 1
if (-not $cert) { throw "Certificat non trouve dans Cert:\LocalMachine\My juste apres -accept" }

$pfxPassPlain = -join ((48..57)+(65..90)+(97..122) | Get-Random -Count 24 | ForEach-Object { [char]$_ })
$pfxPass = ConvertTo-SecureString -String $pfxPassPlain -AsPlainText -Force
Export-PfxCertificate -Cert $cert -FilePath C:\vault-new.pfx -Password $pfxPass
(New-Object System.Security.Cryptography.X509Certificates.X509Certificate2('C:\vault-new.pfx', $pfxPassPlain)).Subject
# attendu : CN=<VAULT_HOSTNAME> -- si ca erreur ici, le probleme est dans l'export, pas le transfert
Set-Content -Path C:\vault-new.pfxpass.txt -Value $pfxPassPlain -NoNewline -Encoding ascii

Export-Certificate -Cert (Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Thumbprint -eq $env:CA_ROOT_THUMBPRINT } | Select-Object -First 1) -FilePath C:\adcs-root.cer -Type CERT
```

Notes utiles si un point coince :
- `certutil -ADCA` : re-decouvrir `<machine CA>\<nom CA>` (`CA_CONFIG`) si la CA a change (pas de ligne litterale `"Config:"` dans sa sortie ; reconstruire depuis `cACertificateDN` = nom de la CA, et l'entree ACL `<DOMAINE>\<NOM_MACHINE>$` = nom de la machine CA).
- `-submit` n'accepte **pas** `-machine` sur certains builds (contexte deja fixe par `-new -machine`) ; `-accept` et `-new` si.
- `Get-PfxCertificate` n'a pas de parametre `-Password` sur PowerShell 5.1 — d'ou le constructeur .NET `X509Certificate2` pour la verification.
- Un PFX exporte depuis un Server 2016/2019 legacy peut etre chiffre en 3DES/SHA1 — gere cote Debian avec `-legacy` plus bas (detection automatique par `install-vault-cert.sh`).

### 🟢 DEBIAN — bloc 1 : dépôt + Docker

```bash
git --version && docker --version && docker compose version
# attendu : les trois commandes repondent (pas de "command not found") - sinon voir bloc optionnel ci-dessous
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

Depuis la racine du dépôt (`deploy/environment.env` déjà rempli — Phase 0) :

```bash
DC_IP=$(grep '^DC_IP=' deploy/environment.env | cut -d= -f2)
DC_NETBIOS=$(grep '^DOMAIN_NETBIOS=' deploy/environment.env | cut -d= -f2)
VAULT_HOSTNAME=$(grep '^VAULT_HOSTNAME=' deploy/environment.env | cut -d= -f2)

smbclient "//$DC_IP/C\$" -U "${DC_NETBIOS}\\Administrator" -c 'get vault-new.pfx; get vault-new.pfxpass.txt; get vault-new.cer; get adcs-root.cer'

# certreq -submit sans -binary sort le certificat en Base64 (PEM), pas en DER -> pas d'-inform der ici
openssl x509 -in vault-new.cer -out vault-new.pem
openssl x509 -in vault-new.pem -noout -subject -ext subjectAltName
# attendu : VAULT_HOSTNAME ET AUTH_HOSTNAME presents dans le SAN -- STOP si l'un des deux manque

# Export-Certificate -Type CERT sort en DER brut (different de certreq -submit) -> -inform der ici
openssl x509 -inform der -in adcs-root.cer -out adcs-root.pem
openssl x509 -in adcs-root.pem -noout -fingerprint -sha1
# attendu : la valeur CA_ROOT_THUMBPRINT de deploy/environment.env

# PFX legacy (3DES/SHA1) -> -legacy obligatoire sur OpenSSL 3.x (fallback -provider legacy automatique dans install-vault-cert.sh)
openssl pkcs12 -legacy -in vault-new.pfx -nocerts -nodes -out vault.key -passin file:vault-new.pfxpass.txt
cat vault-new.pem adcs-root.pem > vault.crt

sudo install -o root -g root -m 644 vault.crt     deploy/02_caddy/certs/vault.crt
sudo install -o root -g root -m 600 vault.key     deploy/02_caddy/certs/vault.key
sudo install -o root -g root -m 644 adcs-root.pem deploy/03_docker/adcs-root.crt

rm -f vault.crt vault.key vault-new.pfx vault-new.pfxpass.txt vault-new.cer vault-new.pem adcs-root.cer adcs-root.pem
```

Si `-legacy` renvoie `unknown option`/`provider "legacy" not found` (module absent du paquet openssl) : remplacer par `openssl pkcs12 -provider legacy -provider default ...` (mêmes autres options).

### 🔵 DC — bloc 2 : purger les fichiers transitoires

```powershell
Remove-Item C:\vault-new.pfx, C:\vault-new.pfxpass.txt, C:\vault-new.cer, C:\vault-new.csr, C:\vault-new.inf, C:\adcs-root.cer -Force -ErrorAction SilentlyContinue
```

### 🟢 DEBIAN — bloc 3 : secrets, déploiement, résolution locale

```bash
cd deploy/03_docker
cp .env.example .env
chmod 600 .env
openssl rand -base64 48   # coller le resultat dans .env -> VW_ADMIN_TOKEN=...
nano .env                 # renseigner VW_ADMIN_TOKEN, VAULT_HOSTNAME, AUTH_HOSTNAME (memes valeurs que deploy/environment.env)

mkdir -p vw-data ../02_caddy/logs   # deploy/02_caddy/logs, PAS deploy/03_docker/caddy/logs (sibling, pas enfant)
docker compose up -d caddy

# hote non domain-joint : pas de DNS pour son propre FQDN
echo "127.0.0.1 $VAULT_HOSTNAME" | sudo tee -a /etc/hosts
echo "127.0.0.1 $AUTH_HOSTNAME"  | sudo tee -a /etc/hosts
```

(`install-vault-cert.sh` fait tous les blocs 3-6 automatiquement, y compris la synchronisation `VAULT_HOSTNAME`/`AUTH_HOSTNAME` entre `deploy/environment.env` et `deploy/03_docker/.env`.)

### 🟢 DEBIAN — Gate Phase 1

```bash
openssl s_client -connect "$VAULT_HOSTNAME:443" -servername "$VAULT_HOSTNAME" </dev/null 2>/dev/null | openssl x509 -noout -issuer
# attendu : issuer = votre CA AD CS (CA_ROOT_THUMBPRINT)

openssl s_client -connect "$VAULT_HOSTNAME:443" -servername "$VAULT_HOSTNAME" -CAfile deploy/03_docker/adcs-root.crt </dev/null 2>&1 | grep "Verify return code"
# attendu : Verify return code: 0 (ok)

docker compose up -d --build vaultwarden
docker exec vaultwarden curl -fsS "https://$VAULT_HOSTNAME/alive"
# attendu : reponse JSON -- resolution interne via l'alias reseau Docker sur "backend", pas de DNS/hosts necessaire cote conteneur
```

---

## Phase 2 — Compte de service + SPN + keytab (DC)

**Fichier** : `deploy/04_kerberos/Setup-KerberosSPNEGO-DC.ps1`

### 🔵 DC

```powershell
# apres . .\deploy\00_Set-Environment.ps1
cd C:\vaultwarden-stack-SSO\deploy\04_kerberos
.\Setup-KerberosSPNEGO-DC.ps1
```

Gates intégrés au script (STOP automatique si échec) : anti-doublon SPN, `msDS-SupportedEncryptionTypes = 24` confirmé, SPN confirmé après `setspn -S`, code de sortie `ktpass` vérifié, kvno affiché, SHA-256 du keytab affiché.

### 🖱️ Refus de logon interactif (GPO) — pas de commande fiable, action GUI requise

Pas de cmdlet dans le module `GroupPolicy` pour les *User Rights Assignments* — édition brute SYSVOL fragile. Sur le DC via `gpmc.msc` :
1. Clic droit sur l'OU cible → *Create a GPO in this domain, and Link it here* → nommer `Deny-Interactive-SvcAccounts`.
2. *Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → User Rights Assignment*.
3. *Deny log on locally* + *Deny log on through Remote Desktop Services* → Add → le groupe `DENY_INTERACTIVE_GROUP` de `deploy/environment.env` (défaut `GG-SvcAccounts-DenyInteractiveLogon`).

### 🔵 DC — Gate

```powershell
gpupdate /force
```
`klist` côté DC n'est **pas** suffisant — la validation réelle se fait Phase 3.

### 🟢 DEBIAN — Transfert du keytab

```bash
smbclient "//$DC_IP/C\$" -U "${DC_NETBIOS}\\Administrator" -c 'get authentik.keytab'
sha256sum authentik.keytab
# comparer avec le hash affiche par le script cote DC (Get-FileHash) -> DOIT etre identique
sudo chown root:root authentik.keytab
sudo chmod 600 authentik.keytab
smbclient "//$DC_IP/C\$" -U "${DC_NETBIOS}\\Administrator" -c 'del authentik.keytab'
```

---

## Phase 2bis — Source LDAP (provisioning des comptes, prérequis Phase 3/5)

**Fichier** : `deploy/04_kerberos/Setup-LDAPBind-DC.ps1`

### 🔵 DC

```powershell
cd C:\vaultwarden-stack-SSO\deploy\04_kerberos
.\Setup-LDAPBind-DC.ps1
```

Crée (idempotent) l'OU `LDAP_SYNC_OU_NAME` (défaut `Vaultwarden` — périmètre à peupler avec les vrais comptes à synchroniser) et le compte de bind `LDAP_BIND_ACCOUNT` (défaut `svc-authentik-ldap`, lecture seule, deny-interactive-logon, aucune délégation). Mot de passe écrit dans `C:\authentik-ldap-bind.txt` (ACL restreinte, jamais affiché).

### 🟢 DEBIAN — transfert

```bash
smbclient "//$DC_IP/C\$" -U "${DC_NETBIOS}\\Administrator" -c 'get authentik-ldap-bind.txt'
openssl s_client -connect "$DC_IP:636" -CAfile deploy/03_docker/adcs-root.crt </dev/null 2>&1 | grep "Verify return code"
# attendu : Verify return code: 0 -- sinon ne pas configurer la Source LDAP en LDAPS tant que ce n'est pas corrige
```

### 🖱️ Source LDAP — action GUI (secret, jamais scriptable vers un tiers)

Directory → Federation & Social login → Create → **LDAP Source** : Server URI `ldaps://<DC_IP>:636`, Bind CN = Bind DN affiché par le script, Bind Password = contenu de `authentik-ldap-bind.txt`, Base DN = `OU=<LDAP_SYNC_OU_NAME>,<DN du domaine>`. Détails complets : `deploy/05_authentik/README.md` §0.

### 🟢 DEBIAN — purge

```bash
shred -u authentik-ldap-bind.txt
```

### Gate

🖱️ Bouton "Sync" de la Source LDAP dans l'admin Authentik → pas d'erreur, comptes de l'OU visibles dans Directory → Users.

---

## Phase 3 — Source Kerberos Authentik

**Fichiers** : `deploy/05_authentik/kerberos-sso-blueprint.yaml` (template), `deploy/05_authentik/render-blueprint.sh`, `deploy/05_authentik/README.md`

### 🟢 DEBIAN

```bash
./deploy/05_authentik/render-blueprint.sh
# produit deploy/05_authentik/kerberos-sso-blueprint.rendered.yaml (jamais versionne),
# avec REALM/DC_IP/DOMAIN_DNS/CLIENT_SUBNETS substitues depuis deploy/environment.env
# (CLIENT_SUBNETS peut lister plusieurs CIDR -- voir l'INFO affiche par le script)

docker exec -i authentik-server ak import_blueprint < deploy/05_authentik/kerberos-sso-blueprint.rendered.yaml
# authentik-server = nom du service Docker (meme VM, meme docker-compose.yml)

base64 -w0 authentik.keytab > authentik.keytab.b64
```

### 🖱️ Upload du keytab — action GUI (secret, jamais scriptable vers un tiers)

Coller le contenu de `authentik.keytab.b64` dans Directory → Federation & Social login → *Kerberos SPNEGO SSO* → champ Keytab. Puis confirmer dans l'UI : `spnego_server_name` vide (volontaire, cf. `deploy/05_authentik/README.md` §5), `user_matching_mode = username_link` (relie au compte LDAP existant, ne crée jamais — `sync_users = false` l'interdit de toute façon), `sync_users = false`.

### 🟢 DEBIAN — purge

```bash
shred -u authentik.keytab.b64
```

### Gates séquentiels

🟠 :
```bash
curl --negotiate -u : "https://$AUTH_HOSTNAME/source/kerberos/kerberos-sso/"
# attendu : 302 (pas 401 final)
```

🖱️ Navigateur poste domaine, **depuis un des réseaux listés dans `CLIENT_SUBNETS`** → `https://<VAULT_HOSTNAME>` → aucun formulaire affiché. 🖱️ Poste **hors** de tous les `CLIENT_SUBNETS` (autre VLAN non listé, ou hors domaine) → formulaire password affiché (fallback). 🖱️ Admin Authentik → Events → un `login` source `kerberos-sso`, sans stage password traversé.

Si vous avez plusieurs réseaux clients (VLAN filaire + WiFi + VPN...), refaire ce test depuis **chacun** d'entre eux : c'est le même CIDR list (`CLIENT_SUBNETS`) qui les couvre tous, un seul rendu du blueprint suffit.

---

## Phase 4 — GPO postes clients

**Fichiers** : `deploy/06_gpo/Deploy-KerberosSSO-GPO.ps1`, `deploy/06_gpo/Set-BitwardenClientPolicy.ps1`, `deploy/06_gpo/firefox-policies.json.example`

### 🔵 DC

```powershell
# apres . .\deploy\00_Set-Environment.ps1
cd C:\vaultwarden-stack-SSO\deploy\06_gpo
.\Deploy-KerberosSSO-GPO.ps1
```

Ce script fait tout, y compris générer et déposer `firefox-policies.json` dans SYSVOL (`\\<DOMAIN_DNS>\SYSVOL\<DOMAIN_DNS>\scripts\firefox-policies.json`) — plus besoin d'éditer/copier un fichier JSON à la main.

### 🟠 Poste de test

```powershell
# alternative/complement a la GPO fleet, pour un test manuel poste par poste
# (apres . .\deploy\00_Set-Environment.ps1, ou en passant -VaultBaseUrl explicitement)
.\deploy\06_gpo\Set-BitwardenClientPolicy.ps1

New-Item -ItemType Directory -Force -Path 'C:\Program Files\Mozilla Firefox\distribution' | Out-Null
Copy-Item -Path "\\$env:DOMAIN_DNS\SYSVOL\$env:DOMAIN_DNS\scripts\firefox-policies.json" -Destination 'C:\Program Files\Mozilla Firefox\distribution\policies.json' -Force

gpupdate /force
gpresult /r
```

Pour un déploiement fleet (pas juste le poste de test), convertir la copie Firefox en GPO Files preference (🖱️ GPMC → Preferences → Windows Settings → Files) — hors périmètre d'une évaluation à un seul poste.

### Gate

🖱️ DevTools navigateur → en-tête `Authorization: Negotiate` sur la requête vers `AUTH_HOSTNAME`. 🖱️ Firefox : `about:policies` → `NegotiateAuth.Trusted` doit lister l'URL Authentik.

🖱️ Signet géré (Chrome `chrome://policy` / Edge `edge://policy` → `ManagedBookmarks`/`ManagedFavorites`, Firefox `about:policies` → `Bookmarks`) : cliquer le signet "Vaultwarden (SSO)" → aucun écran email/identifiant affiché, redirection SPNEGO immédiate vers `https://<VAULT_HOSTNAME>/#/sso?identifier=00000000-01DC-01DC-01DC-000000000000`. Cet identifiant précis (pas une valeur lisible arbitraire) est requis — voir le commentaire dans `Deploy-KerberosSSO-GPO.ps1` : OIDCWarden expose une route sans garde d'appartenance à l'organisation uniquement sur cette valeur, nécessaire pour que l'écran de définition du mot de passe principal (enrollment TDE) se charge correctement. Ce lien fonctionne indépendamment de `SSO_ONLY` (c'est un raccourci client, pas une restriction serveur) — testable dès maintenant en le collant manuellement dans la barre d'adresse, sans attendre le déploiement GPO fleet.

**Ce lien SSO est générique** : le même identifiant magique fonctionne pour n'importe quel utilisateur, ce n'est pas une valeur personnalisée par compte. Ce qui diffère d'un utilisateur/poste à l'autre : (a) le compte AD doit déjà avoir été synchronisé par la Source LDAP (Phase 2bis) avant la première tentative Kerberos — pas de synchronisation automatique à la volée ; (b) l'utilisateur doit déjà avoir une invitation en attente dans l'Organization Vaultwarden (Phase 5) pour voir l'écran TDE plutôt que le parcours OIDC standard ; (c) le poste doit avoir reçu la GPO (`gpupdate /force` effectif) pour bénéficier du signet/négociation automatique — sinon repli sur le formulaire classique, jamais une erreur bloquante.

---

## Phase 5 — Bascule OIDCWarden + TDE

**Fichiers** : `deploy/03_docker/Dockerfile`, `deploy/03_docker/docker-compose.yml`, `deploy/03_docker/.env.example`, `docs/02_risk_analysis_tde.md`

### 🟢 DEBIAN — bloc 1 : backup, secrets

```bash
cd deploy/03_docker
tar czf ../../backup-vw-data-$(date +%Y%m%d-%H%M%S).tar.gz vw-data/
mkdir -p /tmp/restore-test
tar xzf ../../backup-vw-data-*.tar.gz -C /tmp/restore-test
sqlite3 /tmp/restore-test/vw-data/db.sqlite3 "PRAGMA integrity_check;"
# attendu : ok
rm -rf /tmp/restore-test

nano .env
# renseigner VW_SSO_CLIENT_ID, VW_SSO_CLIENT_SECRET, VW_SSO_AUTHORITY
# (VW_SSO_AUTHORITY = coller VERBATIM l'issuer depuis https://<AUTH_HOSTNAME>/application/o/<slug>/.well-known/openid-configuration)
# PG_PASS / AUTHENTIK_SECRET_KEY deja generes par install-vault-cert.sh en Phase 1 -- rien a faire ici
```

### 🟢 DEBIAN — bloc 2 : build et déploiement

```bash
cd deploy/03_docker
docker compose build
docker compose up -d
docker compose logs -f vaultwarden   # surveiller le demarrage / erreurs SSO_AUTHORITY
```

### 🖱️ Organization + policies TDE, break-glass — actions GUI (admin OIDCWarden `/admin`)

1. Créer l'Organization cible, activer **Single Organization** puis **Account Recovery Administration** (auto-enrollment), mapper le groupe AD.
2. **Chaque nouvel utilisateur** doit être invité explicitement dans cette Organization avant sa première connexion SSO pour bénéficier du parcours TDE passwordless — sans invitation, il suit le parcours OIDC standard (mot de passe principal classique à définir).
3. **Avant** de passer `SSO_ONLY=true` : créer un compte break-glass local (email hors domaine dédié), master password fort scellé, exclu de l'Organization SSO.

### Gates (manuels, navigateur)

🖱️ Login SSO compte test → flux complet sans régression → visible `/admin`. 🖱️ Gate TDE : onboarding → device approval → login N+2 → aucun master password demandé. 🖱️ Gate break-glass : login réussi même après passage à `SSO_ONLY=true`. 🖱️ Gate multi-utilisateur : répéter avec un **second** compte AD jamais utilisé auparavant (nouveau, synchronisé Phase 2bis, invité à l'Organization) pour confirmer que rien n'est câblé sur le premier compte de test.

### 🟢 DEBIAN — Bascule SSO_ONLY (uniquement après les gates ci-dessus validés)

```bash
sed -i 's/VW_SSO_ONLY=false/VW_SSO_ONLY=true/' .env
docker compose up -d vaultwarden
```

---

## Phase 6 — Hygiène, supervision

**Fichier** : `docs/03_supervision_siem.md`

```bash
shred -u ../../backup-vw-data-*.tar.gz   # chemin relatif a deploy/03_docker (cwd apres Phase 5) ; adapter si vous avez change de repertoire -- si conserve le temps du test uniquement, sinon archiver en lieu sur avant de supprimer
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
- [ ] `deploy/environment.env` (secrets absents mais contient votre topologie réseau) : classer comme sensible au même titre que `.env`, ne jamais le committer (déjà couvert par `.gitignore`).

---

## Règles d'exécution (rappel)

1. Chaque bloc se colle d'une traite sur la machine indiquée par sa pastille ; un **gate** reste un point d'arrêt — vérifier la sortie attendue avant de passer au bloc suivant.
2. Tout écart entre sortie observée et attendue = STOP + diagnostic, pas de contournement.
3. Aucun secret dans les réponses, les logs, ou les fichiers versionnés — `deploy/environment.env` et `.env` restent locaux, jamais commités.
4. Versions épinglées partout (Dockerfile OIDCWarden, `AUTHENTIK_TAG`) — revérifier avant chaque build.
5. Les étapes marquées 🖱️ sont GUI par nature (secret binaire, wizard, ou réglage sans cmdlet fiable).
