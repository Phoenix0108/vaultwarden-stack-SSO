# Runbook — Installation & configuration propre de Vaultwarden SSO OIDC ↔ AD FS

> **Approche Security by Design** : sécurité intégrée à chaque étape (analyse de risque, moindre privilège, segmentation, hardening, supervision, résilience, IAM, conformité).
> **Public** : administrateur système/réseau spécialisé cybersécurité.
> **Prérequis** : ce runbook suppose l'ordre des couches. **Une étape = une validation** avant de passer à la suivante. Les valeurs réelles sont en **Annexe** (accès restreint).

---

## Nomenclature (placeholders — voir Annexe pour les valeurs)

| Placeholder | Rôle |
|---|---|
| `<ADFS_FQDN>` / `<ADFS_IP>` | Serveur AD FS (= DC/CA en lab) |
| `<VWHOST_IP>` | Hôte Docker Vaultwarden |
| `<CLIENT_SUBNET>` | Sous-réseau des postes clients SSO |
| `<VAULT_FQDN>` | FQDN public Vaultwarden |
| `<DOMAIN_DNS>` / `<DOMAIN_NB>` | Domaine AD (FQDN / NetBIOS) |
| `<GRP_VW>` | Groupe AD d'accès (mode "groupe restreint") |
| `<CLIENT_ID>` | Identifier de la Server Application AD FS |
| `<VW_EGRESS_SUBNET>` | Subnet Docker egress AD FS (ex. `172.31.9.0/29`) |
| `<VERSION>` | Version Vaultwarden épinglée (ex. `1.36.0`) |

---

## Décision préalable : modèle d'accès (À CHOISIR)

Deux modes selon le besoin. Le runbook couvre les deux ; choisis à l'étape 3.4.

| Mode | Qui accède | Politique AD FS | Usage |
|---|---|---|---|
| **A — Groupe restreint** (recommandé par défaut) | Membres de `<GRP_VW>` uniquement | Règle d'autorisation `groupsid == <SID>` | Déploiement ciblé, moindre privilège strict |
| **B — Tous les utilisateurs du domaine** | Tout compte AD activé | `PermitEveryone` (built-in) | Cas où le coffre doit être ouvert à tout le domaine |

> **Analyse de risque du mode B** : ouvrir à tout le domaine augmente la surface (tout compte compromis = accès au SSO Vaultwarden ; auto-provisionnement JIT de masse). À **compenser impérativement** par : MFA par relying party (obligatoire), Extranet Smart Lockout, supervision renforcée des provisionnements JIT, et revue périodique des comptes créés. Le mode A reste préférable dès qu'un périmètre d'utilisateurs peut être défini.

---

## Étape 1 — Socle Active Directory

### 1.1 DNS de la NIC du DC (résilience de résolution)
```powershell
# Le DC resout sur son IP reelle en primaire, loopback en secours — JAMAIS un resolveur externe (fuite OPSEC)
Set-DnsClientServerAddress -InterfaceAlias 'Ethernet' -ServerAddresses <ADFS_IP>,127.0.0.1
```

### 1.2 NLA en démarrage différé (catégorisation fiable au boot)
```powershell
sc.exe config NlaSvc start= delayed-auto        # espace obligatoire apres "start="
Start-Service NlaSvc
# Forcer re-evaluation (EN CONSOLE LOCALE si RDP sur cette NIC) :
Disable-NetAdapter -Name 'Ethernet' -Confirm:$false ; Start-Sleep 3 ; Enable-NetAdapter -Name 'Ethernet'
Get-NetConnectionProfile | Select InterfaceAlias, NetworkCategory   # ATTENDU : DomainAuthenticated
```
> **Risque** : NIC de DC en `Public` = toutes les règles firewall Domain inertes. Vérification bloquante avant de continuer.

### 1.3 Utilisateurs & groupe
```powershell
# Attribut mail OBLIGATOIRE (identifiant d'appariement OIDC)
Set-ADUser -Identity <user> -EmailAddress '<user>@<DOMAIN_DNS>' -UserPrincipalName '<user>@<DOMAIN_DNS>'

# Mode A : groupe d'acces dedie + membres
New-ADGroup -Name '<GRP_VW>' -GroupScope Global -GroupCategory Security
Add-ADGroupMember -Identity '<GRP_VW>' -Members <user>

# Controle de coherence upn==mail (prerequis a documenter, cf. deroga eventuelle)
Get-ADUser -Filter {Enabled -eq $true} -Properties mail,userPrincipalName |
  Where-Object { $_.mail -and ($_.mail -ne $_.userPrincipalName) } |
  Select SamAccountName, mail, userPrincipalName    # VIDE attendu
```
> **Validation étape 1** : `NetworkCategory = DomainAuthenticated`, attribut `mail` peuplé, groupe créé (mode A).

---

## Étape 2 — PKI (AD CS)

### 2.1 Export de la racine (partie publique uniquement)
```powershell
$root = Get-ChildItem Cert:\LocalMachine\Root |
        Where-Object { $_.Subject -eq 'CN=<CA_ROOT_CN>, ...' } | Select -First 1
Export-Certificate -Cert $root -FilePath C:\adcs-root.cer -Type CERT
$root | Format-List Subject, Issuer, Thumbprint, NotAfter   # noter le Thumbprint (controle integrite)
```
> **Risque** : ne JAMAIS exporter la clé privée de l'AC. `-Type CERT` = public seul. Surveiller `NotAfter` (alerte J-90 SIEM).

> **Cible durcissement** : PKI deux niveaux (racine offline). En lab, mono-niveau accepté et documenté.

---

## Étape 3 — Fournisseur d'identité AD FS

### 3.1 Application Group (Server Application + Web API)
Via l'assistant AD FS Management ou PowerShell. Points clés :
- **Redirect URI** = `https://<VAULT_FQDN>/identity/connect/oidc-signin` (sensible casse + slash final).
- Server Application = client **confidentiel** (secret généré).

### 3.2 Secret client
```powershell
$app = Get-AdfsServerApplication -Name 'Vaultwarden Server'
$new = Set-AdfsServerApplication -TargetIdentifier $app.Identifier -ResetClientSecret -PassThru
"CLIENT_ID     = $($app.Identifier)"
"CLIENT_SECRET = $($new.ClientSecret)"    # AFFICHE UNE FOIS — copier immediatement, stocker en coffre
```
> Rotation planifiée : `-ChangeClientSecret` (sans coupure). Incident : `-ResetClientSecret` (révocation immédiate).

### 3.3 Scopes — dont `allatclaims` (CONDITION CRITIQUE)
```powershell
# La permission existe deja apres creation -> MODIFIER (ne pas Grant- qui echoue en MSIS7626)
$perm = Get-AdfsApplicationPermission | Where-Object { $_.ClientRoleIdentifier -eq '<CLIENT_ID>' }
Set-AdfsApplicationPermission -TargetIdentifier $perm.ObjectIdentifier -AddScope 'allatclaims'
# Verifier :
(Get-AdfsApplicationPermission | ? ClientRoleIdentifier -eq '<CLIENT_ID>').ScopeNames
# ATTENDU : {allatclaims, email, profile, openid, offline_access}
```
> **Sans `allatclaims`, AD FS 2016+ n'émet AUCUN claim custom (dont `email`) dans l'id_token.** C'était le blocage final.
> **Analyse de risque `allatclaims`** : place TOUS les claims des transform rules dans l'id_token → **restreindre les transform rules au strict minimum** (§3.5). L'audit event 501 permet de vérifier ce qui part réellement.

### 3.4 Politique d'accès — selon le mode choisi

**Mode A (groupe restreint)** :
```powershell
$grpSid = (Get-ADGroup '<GRP_VW>').SID.Value
$authz = @"
@RuleTemplate = "Authorization"
@RuleName = "Permit <GRP_VW> only"
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid", Value == "$grpSid"]
 => issue(Type = "http://schemas.microsoft.com/authorization/claims/permit", Value = "PermitUsersWithClaim");
"@
Set-AdfsWebApiApplication -TargetIdentifier '<CLIENT_ID>' -IssuanceAuthorizationRules $authz
```

**Mode B (tous les utilisateurs du domaine)** :
```powershell
# Politique built-in "Permit everyone" (nom localise -> verifier via Get-AdfsAccessControlPolicy)
Set-AdfsWebApiApplication -TargetIdentifier '<CLIENT_ID>' `
  -AccessControlPolicyName 'Permit everyone'
# OU regle d'autorisation permissive :
$authzAll = '=> issue(Type = "http://schemas.microsoft.com/authorization/claims/permit", Value = "true");'
Set-AdfsWebApiApplication -TargetIdentifier '<CLIENT_ID>' -IssuanceAuthorizationRules $authzAll
```
> Mode B : activer MFA par RP + Extranet Lockout (§3.6) est **obligatoire**, pas optionnel.

### 3.5 Règle d'émission des claims (email, MINIMALE)
```powershell
$rules = @'
@RuleTemplate = "LdapClaims"
@RuleName = "Vaultwarden email"
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"]
 => issue(store = "Active Directory",
    types = ("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"),
    query = ";mail;{0}", param = c.Value);
'@
Set-AdfsWebApiApplication -TargetIdentifier '<CLIENT_ID>' -IssuanceTransformRules $rules
Restart-Service adfssrv    # micro-coupure d'auth (contrainte SPOF, hors usage)
```
> **NE PAS émettre `email_verified`** (AD FS le sérialise en chaîne `"true"` → Vaultwarden rejette : *invalid type string, expected boolean*). Couvert par `SSO_ALLOW_UNKNOWN_EMAIL_VERIFICATION=true`.
> **Moindre privilège** : cette règle n'émet QUE `emailaddress`. Ne pas ajouter de groupes/attributs (qu'`allatclaims` exposerait tous).

### 3.6 Durcissement IdP
```powershell
Set-AdfsProperties -EnableExtranetLockout $true `
  -ExtranetLockoutThreshold 5 -ExtranetObservationWindow (New-TimeSpan -Minutes 15) `
  -ExtranetLockoutMode ADFSSmartLockoutLogOnly    # observation puis Enforce
# Audit d'emission (diagnostic + SIEM) :
auditpol /set /subcategory:"{0CCE9222-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
```
> MFA par relying party sur cette application (coffre = cible haute valeur), via adaptateur certificat AD CS ou WebAuthn.

> **Validation étape 3** : `ScopeNames` inclut `allatclaims`, politique d'accès posée, règle email en place.

---

## Étape 4 — Pare-feu AD FS (segmentation, moindre privilège)

```powershell
# Posture explicite (sortir du NotConfigured pour l'auditabilite)
Set-NetFirewallProfile -Name Domain,Private,Public -DefaultInboundAction Block -DefaultOutboundAction Allow

# Regle inbound 443 SCOPEE au subnet client (front + back-channel), profil Domain (fail-safe)
$fw = @{
  DisplayName='ADFS-HTTPS-Inbound-Clients'; Direction='Inbound'; Action='Allow'
  Protocol='TCP'; LocalPort=443; RemoteAddress='<CLIENT_SUBNET>'; Profile='Domain'; Enabled='True'
}
New-NetFirewallRule @fw
Set-NetFirewallProfile -Name Domain -LogBlocked True   # detection : DROP 443 hors subnet = reconnaissance
```
> **NE JAMAIS `-RemoteAddress Any`** (exposerait le tier-0). Cible : porter la règle en **GPO** liée à l'OU AD FS.
> **Cible** : publication via **WAP en DMZ** (AD FS interne non exposé).

> **Validation étape 4** : depuis l'hôte Docker, `Test-NetConnection <ADFS_FQDN> -Port 443` → `True`.

---

## Étape 5 — Réseau & conteneurs Docker

Voir `deploy/docker/docker-compose.yml` et `deploy/firewall/`. Points clés :
- `backend: internal: true` (Vaultwarden joignable uniquement via Caddy).
- `adfs_egress` (bridge `/29`) + allow-list `DOCKER-USER` (default-deny, seul `<ADFS_IP>:443` autorisé).
- Persistance via unité systemd `After=docker.service` (**pas** `netfilter-persistent`).
- Durcissement conteneur : `no-new-privileges`, `cap_drop: [ALL]`.

```bash
# Appliquer les regles d'egress (script idempotent) puis persister via systemd
sudo /usr/local/sbin/vw-egress-fw.sh
sudo systemctl enable --now vw-egress-fw.service
iptables -L DOCKER-USER -n -v --line-numbers    # 4 regles, DROP counter = 0
```

> **Validation étape 5** : `docker inspect vaultwarden` montre `backend` ET `adfs_egress` ; règles DOCKER-USER présentes.

---

## Étape 6 — TLS (confiance CA AD CS + épinglage version)

```bash
# Transferer adcs-root.cer vers l'hote (base64 copier-coller ou SMB), PUIS verifier l'empreinte
openssl x509 -inform der -in adcs-root.cer -out deploy/docker/adcs-root.crt
openssl x509 -in deploy/docker/adcs-root.crt -noout -fingerprint -sha1   # == Thumbprint AD CS
```
Image dérivée (`deploy/docker/Dockerfile`) : `FROM vaultwarden/server:<VERSION>` + `COPY adcs-root.crt` + `update-ca-certificates`.

```bash
docker compose build vaultwarden && docker compose up -d vaultwarden
# Validation TLS depuis le CONTENEUR (plan de production) :
docker exec vaultwarden sh -c 'curl -fsS https://<ADFS_FQDN>/adfs/.well-known/openid-configuration | head -c 200'
```
> **Risque** : jamais `--insecure`. On étend la confiance à la CA interne, on ne désactive pas la vérification.

> **Validation étape 6** : le `curl` conteneur renvoie du JSON (`issuer`, endpoints).

---

## Étape 7 — Configuration SSO Vaultwarden

Via `/admin` ou variables d'environnement (voir `deploy/vaultwarden/vaultwarden.env.example`). Paramètres clés :

| Champ | Valeur | Justification |
|---|---|---|
| `SSO_ENABLED` | `true` | — |
| `SSO_ONLY` | `true` (ou `false` en phase de test) | annuaire autoritaire (prévoir break-glass) |
| `SSO_CLIENT_ID` | `<CLIENT_ID>` | — |
| `SSO_CLIENT_SECRET` | *(secret AD FS)* | via `SSO_CLIENT_SECRET_FILE` en cible |
| `SSO_AUTHORITY` | `https://<ADFS_FQDN>/adfs` | **casse EXACTE de l'issuer** |
| `SSO_SCOPES` | `email profile offline_access` | `openid` ajouté auto — ne pas le dupliquer |
| `SSO_ALLOW_UNKNOWN_EMAIL_VERIFICATION` | `true` | AD FS n'émet pas `email_verified` |
| `SSO_PKCE` (UI: Use PKCE) | activé | durcit contre interception du code |
| `Allow email association` | **décoché** | pas de rattachement sans preuve |
| `Use SSO only for auth not session lifecycle` | **décoché** | session liée au jeton (révocation sur désactivation) |
| `Log all tokens` / `SSO_DEBUG_TOKENS` | **désactivé** (sauf debug ponctuel) | jetons en clair = secret |

> **Validation étape 7** : login `<user>` → redirection AD FS → retour → master password → `/admin → Users` affiche le compte JIT (*Verified*).

---

## Étape 8 — Hygiène de clôture (OBLIGATOIRE)

```bash
# Retirer SSO_DEBUG_TOKENS du compose, decocher "Log all tokens", LOG_LEVEL=info
docker compose up -d vaultwarden
# Purger les logs contenant des jetons en clair
truncate -s 0 /var/lib/docker/containers/$(docker inspect -f '{{.Id}}' vaultwarden)/*-json.log
```
Côté AD FS : repasser `SSO_DEBUG` si activé, revoir `AuditLevel`. Supprimer captures d'écran de debug (contiennent `code`, `code_verifier`, `ssoToken`).

> **Traçabilité** : consigner la fenêtre de debug (qui/quand/pourquoi/purge) dans le journal d'exploitation.

---

## Supervision / SIEM (à câbler)

| Source | Événements | Détection |
|---|---|---|
| AD FS (`Security`, event **501** `Application Generated`, `AD FS/Admin`) | émission jeton, claims émis | présence email, claims anormaux |
| AD FS 1200 / 1203 | jeton émis / refus politique | accès hors groupe (mode A) |
| DC Sécurité 4624/4625 | succès/échec auth | credential stuffing |
| Firewall Windows `pfirewall.log` | DROP 443 hors `<CLIENT_SUBNET>` | reconnaissance IdP |
| Hôte Docker `VW-EGRESS-DROP` | compteur ≠ 0 | sortie conteneur anormale = compromission |
| Vaultwarden (stdout) | `login`, appariement | provisionnement JIT anormal |

---

## Matrice de déprovisionnement (IAM)

| Couche | Fermée par | Latence |
|---|---|---|
| Nouvelle connexion | Désactivation compte AD | immédiate |
| Session active | Échec refresh (offline_access + session bindée) | ≤ durée access/refresh token |
| Coffre déchiffré en cache local | **Aucune** action AD | jusqu'à ré-auth en ligne |
| Compte Vaultwarden | **Manuel** dans `/admin` (pas de SCIM) | manuelle |

> **Procédure de départ** : (a) désactiver/supprimer le compte dans `/admin`, (b) retirer des organisations/`<GRP_VW>`, (c) **rotation des secrets partagés** accessibles. Pas de SCIM → déprovisionnement partiellement manuel.

---

## Annexe — Valeurs réelles (ACCÈS RESTREINT — ne pas diffuser)

| Placeholder | Valeur (lab) |
|---|---|
| `<ADFS_FQDN>` | `SRVADTEST.vaultwardensso.local` |
| `<ADFS_IP>` | `192.168.100.93` |
| `<VWHOST_IP>` | `192.168.100.89` |
| `<CLIENT_SUBNET>` | `192.168.100.0/24` |
| `<VAULT_FQDN>` | `vault.vaultwardensso.local` |
| `<DOMAIN_DNS>` / `<DOMAIN_NB>` | `vaultwardensso.local` / `VAULTWARDENSSO` |
| `<GRP_VW>` | `grp-vaultwarden` |
| `<CLIENT_ID>` | `d2d6941a-d29e-4efc-8f1d-2d0058ad257d` |
| `<VW_EGRESS_SUBNET>` | `172.31.9.0/29` |
| `<VERSION>` | `1.36.0` |
| `<CA_ROOT_CN>` | `vaultwardensso-SRVADTEST-CA` |
| Client secret | *(coffre — jamais en clair sur support non chiffré)* |
