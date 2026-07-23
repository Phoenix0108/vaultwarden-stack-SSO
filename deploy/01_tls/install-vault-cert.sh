#!/usr/bin/env bash
# =============================================================================
# install-vault-cert.sh
# Provisionne l'hote Docker de zero (depot, Docker, paquets requis), recupere
# le certificat + la racine AD CS generes par New-VaultCertDC.ps1 sur le DC,
# les convertit, les assemble, les installe dans le depot, deploie
# Caddy/Vaultwarden et valide les gates. Se lance depuis n'importe ou : sans
# depot present, il le clone (REPO_URL requis) ; depuis un depot deja cloné,
# il l'utilise tel quel.
# -----------------------------------------------------------------------------
# Resilient : installe les paquets manquants (git, docker, smbclient, openssl)
# plutot que d'echouer dessus ; retries avec backoff sur le transfert SMB
# (reseau lab peu fiable possible) ; detection automatique du fallback
# openssl -legacy vs -provider ; verification a chaque etape (SAN, empreinte
# SHA-1, gates TLS) avec arret net et message diagnostique si un controle
# echoue -- jamais de contournement silencieux ; nettoyage systematique des
# fichiers secrets transitoires meme en cas d'echec (trap EXIT) ; idempotent
# sur le clone, l'installation des paquets, .env et /etc/hosts (ne repete ni
# n'ecrase ce qui est deja en place).
# -----------------------------------------------------------------------------
# Menace couverte : cle privee et mot de passe PFX jamais loggues ; ADMIN_TOKEN
# genere avec suffisamment d'entropie (openssl rand) si .env n'existe pas
# encore ; verification TLS jamais desactivee (-CAfile, jamais -k/--insecure) ;
# paquets installes depuis le depot officiel Docker (cle GPG verifiee), jamais
# via un script tiers non verifie.
# Privilege minimal : sudo requis pour l'installation de paquets systeme et
# pour install/tee vers des chemins root-owned deja definis par
# docker-compose.yml -- rien au-dela de ce perimetre.
# Residuel : si SMB_PASSWORD est fourni en variable d'environnement, il reste
# brievement visible dans la table des process (ps) le temps de l'appel
# smbclient -- preferer la saisie interactive si le contexte le permet.
# -----------------------------------------------------------------------------
# Variables d'environnement reconnues (toutes optionnelles sauf REPO_URL si le
# depot n'est pas deja cloné) :
#   REPO_URL, REPO_DIR (def. vaultwarden-stack-SSO), REPO_BRANCH
#   DC_IP, DC_USER, SMB_PASSWORD, SMB_RETRIES
#   SPN_HOSTNAME, AUTH_HOSTNAME, ROOT_THUMBPRINT
# Toutes (sauf REPO_*/SMB_*) sont normalement absentes de l'environnement
# appelant : ce script sourced automatiquement deploy/environment.env (copie
# remplie de 00_environment.env.example) des que le depot est disponible --
# DC_IP/AUTH_HOSTNAME viennent alors directement de ce fichier, SPN_HOSTNAME
# de VAULT_HOSTNAME, ROOT_THUMBPRINT de CA_ROOT_THUMBPRINT, DC_USER de
# DOMAIN_NETBIOS. Voir plus bas (etape 0b) -- passer une variable explicitement
# dans l'environnement appelant reste prioritaire sur environment.env.
# Tout passe par Caddy : ce script n'a plus besoin de connaitre l'IP reelle
# d'Authentik (pas d'extra_hosts a renseigner) -- seul AUTHENTIK_UPSTREAM dans
# .env (docker-compose.yml) en a besoin, a configurer avant la Phase 5.
# =============================================================================
set -euo pipefail

SMB_RETRIES="${SMB_RETRIES:-3}"
REPO_URL="${REPO_URL:-}"
REPO_DIR="${REPO_DIR:-vaultwarden-stack-SSO}"
REPO_BRANCH="${REPO_BRANCH:-claude/sso-kerberos-vaultwarden-ad-rzg3w0}"

info(){ echo -e "\033[36m[INFO]\033[0m $*"; }
ok(){   echo -e "\033[32m[ OK ]\033[0m $*"; }
warn(){ echo -e "\033[33m[WARN]\033[0m $*"; }
fail(){ echo -e "\033[31m[FAIL]\033[0m $*" >&2; exit 1; }

apt_prepare() {
    [ -n "${_APT_PREPARED:-}" ] && return 0
    # Installeur Debian (DVD/ISO) laisse souvent une source cdrom:// dans
    # sources.list ; sans le disque monte, apt-get update echoue dessus et
    # (avec set -e) tue le script meme si les depots reseau fonctionnent.
    if grep -q '^deb cdrom:' /etc/apt/sources.list 2>/dev/null; then
        warn "Source cdrom:// detectee dans sources.list, desactivee (Release introuvable sans le disque monte)"
        sudo sed -i '/^deb cdrom:/s/^/#/' /etc/apt/sources.list
    fi
    sudo apt-get update -qq \
        || warn "apt-get update a signale une erreur sur au moins une source -- poursuite, le pass/fail reel se joue sur apt-get install"
    _APT_PREPARED=1
}

apt_install() {
    warn "$* absent, installation via apt-get"
    apt_prepare
    sudo apt-get install -y "$@"
}

command -v git >/dev/null || apt_install git

# --- 0. Depot : detecter, ou cloner si absent ---------------------------------------
if git -C . rev-parse --show-toplevel >/dev/null 2>&1 \
        && [ -f "$(git rev-parse --show-toplevel)/deploy/01_tls/install-vault-cert.sh" ]; then
    REPO_ROOT="$(git rev-parse --show-toplevel)"
    info "Depot deja present : $REPO_ROOT"
elif [ -d "$REPO_DIR/.git" ]; then
    REPO_ROOT="$(cd "$REPO_DIR" && pwd)"
    info "Depot deja clone : $REPO_ROOT"
else
    [ -n "$REPO_URL" ] || fail "Depot absent et REPO_URL non renseigne -- relancer avec REPO_URL=<url_du_depot> $0"
    info "Clonage du depot ($REPO_URL)"
    git clone "$REPO_URL" "$REPO_DIR"
    REPO_ROOT="$(cd "$REPO_DIR" && pwd)"
fi
cd "$REPO_ROOT"
git checkout "$REPO_BRANCH" 2>/dev/null || warn "Checkout $REPO_BRANCH ignore (branche absente ou deja dessus)"

# Mise a jour non destructive : un clone deja present peut dater d'une execution
# precedente et manquer des correctifs plus recents (vecu en pratique -- le
# relais ci-dessous executait une copie perimee sans ce pull). --ff-only refuse
# proprement (sans rien ecraser) s'il y a des modifications locales sur des
# fichiers suivis par git ; les fichiers ignores (.env, certs, vw-data) ne sont
# de toute facon jamais concernes.
info "Mise a jour du depot (git pull --ff-only)"
DIRTY="$(git status --porcelain)"
if [ -n "$DIRTY" ]; then
    warn "Depot local modifie -- pull ignore pour ne rien ecraser. Fichiers concernes :"
    echo "$DIRTY" | sed 's/^/    /'
    warn "Ces modifications empechent toute mise a jour automatique (ce script continuera avec cette copie locale, potentiellement perimee)."
    warn "Pour repasser sur la version officielle du depot (perd les modifications locales listees ci-dessus) :"
    warn "    git -C '$REPO_ROOT' checkout -- . && git -C '$REPO_ROOT' pull --ff-only origin $REPO_BRANCH"
elif ! git pull --ff-only origin "$REPO_BRANCH" --quiet; then
    warn "git pull --ff-only a echoue (reseau ? credentials ? deja a jour ?) -- poursuite avec la copie locale telle quelle"
fi

# --- 0b. Config centrale : sourcer deploy/environment.env si present --------------
ENV_FILE="$REPO_ROOT/deploy/environment.env"
if [ -f "$ENV_FILE" ]; then
    info "Chargement de la config centrale : $ENV_FILE"
    set -a
    # shellcheck disable=SC1090
    source "$ENV_FILE"
    set +a
else
    warn "$ENV_FILE absent -- copier deploy/00_environment.env.example vers deploy/environment.env et le renseigner (evite de repasser DC_IP=... etc. en variables d'environnement a chaque execution)."
fi

DC_IP="${DC_IP:-}"
AUTH_HOSTNAME="${AUTH_HOSTNAME:-}"
SPN_HOSTNAME="${SPN_HOSTNAME:-${VAULT_HOSTNAME:-}}"
ROOT_THUMBPRINT="${ROOT_THUMBPRINT:-${CA_ROOT_THUMBPRINT:-}}"
if [ -z "${DC_USER:-}" ] && [ -n "${DOMAIN_NETBIOS:-}" ]; then
    DC_USER="${DOMAIN_NETBIOS}\\Administrator"
fi
DC_USER="${DC_USER:-}"

for v in DC_IP DC_USER SPN_HOSTNAME AUTH_HOSTNAME ROOT_THUMBPRINT; do
    [ -n "${!v}" ] || fail "$v manquant -- renseigner deploy/environment.env (copie de deploy/00_environment.env.example), ou passer $v=... explicitement en variable d'environnement."
done
[ "$ROOT_THUMBPRINT" != "CHANGE_ME_SHA1_THUMBPRINT" ] || fail "CA_ROOT_THUMBPRINT est encore au placeholder dans $ENV_FILE -- le renseigner avant de continuer."

# Relais vers la copie du depot (a jour, avec tous les correctifs) si ce script
# a ete lance en standalone avant que le depot n'existe -- evite d'executer une
# copie perimee une fois le vrai depot disponible. Garde anti-boucle : _VAULT_CERT_REEXEC.
CANONICAL="$REPO_ROOT/deploy/01_tls/install-vault-cert.sh"
if [ -z "${_VAULT_CERT_REEXEC:-}" ] && [ -f "$CANONICAL" ] \
        && [ "$(readlink -f "$0" 2>/dev/null || echo "$0")" != "$(readlink -f "$CANONICAL")" ]; then
    info "Relais vers la copie du depot : $CANONICAL"
    exec env _VAULT_CERT_REEXEC=1 REPO_URL="$REPO_URL" REPO_DIR="$REPO_DIR" REPO_BRANCH="$REPO_BRANCH" \
        DC_IP="$DC_IP" DC_USER="$DC_USER" SPN_HOSTNAME="$SPN_HOSTNAME" AUTH_HOSTNAME="$AUTH_HOSTNAME" \
        ROOT_THUMBPRINT="$ROOT_THUMBPRINT" SMB_RETRIES="$SMB_RETRIES" \
        bash "$CANONICAL" "$@"
fi

TMP_FILES=(vault-new.pfx vault-new.pfxpass.txt vault-new.cer vault-new.pem adcs-root.cer adcs-root.pem)
cleanup() {
    info "Nettoyage des fichiers transitoires locaux"
    ( cd "$REPO_ROOT" && rm -f "${TMP_FILES[@]}" ) 2>/dev/null || true
}
trap cleanup EXIT

# --- 0b. Paquets requis : installer ce qui manque plutot que d'echouer dessus ------
command -v smbclient >/dev/null || apt_install smbclient
command -v openssl   >/dev/null || apt_install openssl
command -v curl      >/dev/null || apt_install curl
command -v gpg       >/dev/null || apt_install gnupg

if ! command -v docker >/dev/null; then
    warn "Docker absent, installation depuis le depot officiel"
    apt_prepare
    curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker.gpg] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
        | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
    # Nouvelle source ajoutee (docker.list) : reindexation necessaire malgre apt_prepare deja passe
    sudo apt-get update -qq \
        || warn "apt-get update a signale une erreur sur au moins une source -- poursuite, le pass/fail reel se joue sur apt-get install"
    sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    sudo systemctl enable --now docker
    ok "Docker installe"
fi
docker compose version >/dev/null 2>&1 || apt_install docker-compose-plugin
ok "Prerequis systeme presents : git, smbclient, openssl, curl, gnupg, docker (+ plugin compose)"

# --- 1. Transfert SMB avec retries ------------------------------------------------
if [ -n "${SMB_PASSWORD:-}" ]; then
    SMB_AUTH="$DC_USER%$SMB_PASSWORD"
else
    SMB_AUTH="$DC_USER"
fi

info "Transfert des fichiers depuis le DC ($DC_IP)"
attempt=1
until smbclient "//$DC_IP/C\$" -U "$SMB_AUTH" \
    -c 'get vault-new.pfx; get vault-new.pfxpass.txt; get vault-new.cer; get adcs-root.cer'
do
    if (( attempt >= SMB_RETRIES )); then
        fail "Transfert SMB echoue apres $SMB_RETRIES tentatives -- verifier reseau/credentials, et que New-VaultCertDC.ps1 a bien tourne sur le DC."
    fi
    warn "Tentative $attempt/$SMB_RETRIES echouee, nouvel essai dans $((attempt*2))s"
    sleep $((attempt*2))
    attempt=$((attempt+1))
done
for f in vault-new.pfx vault-new.pfxpass.txt vault-new.cer adcs-root.cer; do
    [ -s "$f" ] || fail "$f absent ou vide apres transfert"
done
ok "4 fichiers transferes"

# --- 2. Conversion certificat serveur (Base64/PEM -- certreq -submit sans -binary) --
openssl x509 -in vault-new.cer -out vault-new.pem \
    || fail "Conversion vault-new.cer -> PEM echouee"
SAN="$(openssl x509 -in vault-new.pem -noout -ext subjectAltName)"
echo "$SAN" | grep -q "$SPN_HOSTNAME" || fail "SAN du certificat ne contient pas $SPN_HOSTNAME -- mauvais certificat, ne pas continuer."
echo "$SAN" | grep -q "$AUTH_HOSTNAME" || fail "SAN du certificat ne contient pas $AUTH_HOSTNAME -- Caddy ne pourra pas servir auth.* avec ce certificat (regenerer avec New-VaultCertDC.ps1 -AuthHostname)."
ok "SAN verifie : $SPN_HOSTNAME et $AUTH_HOSTNAME presents"

# --- 3. Conversion racine AD CS (DER brut -- Export-Certificate -Type CERT) ---------
openssl x509 -inform der -in adcs-root.cer -out adcs-root.pem \
    || fail "Conversion adcs-root.cer -> PEM echouee"
fp=$(openssl x509 -in adcs-root.pem -noout -fingerprint -sha1 | cut -d= -f2 | tr -d ':')
if [ "$fp" != "$ROOT_THUMBPRINT" ]; then
    fail "Empreinte racine inattendue ($fp != $ROOT_THUMBPRINT) -- mauvaise racine, ne pas continuer."
fi
ok "Empreinte racine verifiee"

# --- 4. Extraction de la cle privee (PFX 3DES/SHA1 legacy sur Server 2016) ----------
info "Extraction de la cle privee du PFX"
PKCS12_ERR="$(mktemp)"
if ! openssl pkcs12 -legacy -in vault-new.pfx -nocerts -nodes -out vault.key \
        -passin file:vault-new.pfxpass.txt 2>"$PKCS12_ERR"; then
    if grep -qi 'unknown option\|provider "legacy" not found' "$PKCS12_ERR"; then
        warn "-legacy indisponible sur ce build openssl, tentative -provider legacy -provider default"
        openssl pkcs12 -provider legacy -provider default -in vault-new.pfx -nocerts -nodes \
            -out vault.key -passin file:vault-new.pfxpass.txt \
            || fail "Extraction de la cle impossible (voir $PKCS12_ERR)"
    else
        cat "$PKCS12_ERR" >&2
        fail "Extraction de la cle privee echouee (Mac verify error persistant -- fichier corrompu au transfert ? comparer sha256sum des deux cotes plutot que re-suspecter le mot de passe)"
    fi
fi
rm -f "$PKCS12_ERR"
ok "Cle privee extraite : vault.key"

# --- 5. Assemblage et installation --------------------------------------------------
cat vault-new.pem adcs-root.pem > vault.crt
sudo install -o root -g root -m 644 vault.crt     deploy/02_caddy/certs/vault.crt
sudo install -o root -g root -m 600 vault.key     deploy/02_caddy/certs/vault.key
sudo install -o root -g root -m 644 adcs-root.pem deploy/03_docker/adcs-root.crt
rm -f vault.crt vault.key
ok "Chaine installee dans deploy/02_caddy/certs et deploy/03_docker"

# --- 6. Secrets applicatifs (.env, idempotent : jamais ecrase s'il existe) ---------
cd deploy/03_docker
if [ ! -f .env ]; then
    info "Creation de .env (nouveaux secrets generes, entropie suffisante)"
    cp .env.example .env
    chmod 600 .env
    token=$(openssl rand -base64 48)
    sed -i "s#VW_ADMIN_TOKEN=.*#VW_ADMIN_TOKEN=${token}#" .env
    ok ".env cree avec VW_ADMIN_TOKEN genere"
else
    warn ".env deja present, non modifie (idempotent) -- verifier VW_ADMIN_TOKEN manuellement si besoin"
fi

# VAULT_HOSTNAME/AUTH_HOSTNAME : pas des secrets, doivent toujours refleter
# deploy/environment.env (source de verite unique pour les hostnames) --
# synchronises sans condition ici, contrairement aux secrets ci-dessous qui
# ne sont jamais regeneres une fois presents.
sync_hostname() {
    local var="$1" val="$2"
    if grep -q "^${var}=" .env 2>/dev/null; then
        sed -i "s#^${var}=.*#${var}=${val}#" .env
    else
        printf '%s=%s\n' "$var" "$val" >> .env
    fi
}
sync_hostname VAULT_HOSTNAME "$SPN_HOSTNAME"
sync_hostname AUTH_HOSTNAME "$AUTH_HOSTNAME"
ok ".env : VAULT_HOSTNAME=$SPN_HOSTNAME AUTH_HOSTNAME=$AUTH_HOSTNAME (synchronise depuis deploy/environment.env)"

# PG_PASS / AUTHENTIK_SECRET_KEY : purs secrets d'entropie (Authentik meme VM,
# meme docker-compose) -- generes automatiquement s'ils sont encore au
# placeholder CHANGE_ME, OU meme totalement ABSENTS de .env (cas vecu : un
# .env cree par une execution anterieure a l'ajout d'Authentik a ce depot ne
# contient pas ces lignes du tout -- un simple grep sur "CHANGE_ME" ne les
# detecte pas et docker compose echoue alors sur "variable ... is missing a
# value"). ensure_secret couvre les deux cas : absent -> ajoute, CHANGE_ME ->
# remplace ; sinon laisse tel quel (idempotent).
ensure_secret() {
    local var="$1" gen_cmd="$2" val
    if ! grep -q "^${var}=" .env 2>/dev/null; then
        val="$(eval "$gen_cmd")"
        printf '%s=%s\n' "$var" "$val" >> .env
        ok "$var absent de .env (ancienne installation), ajoute et genere"
    elif grep -q "^${var}=CHANGE_ME" .env 2>/dev/null; then
        val="$(eval "$gen_cmd")"
        sed -i "s#^${var}=.*#${var}=${val}#" .env
        ok "$var genere (placeholder remplace)"
    fi
}
ensure_secret PG_PASS "openssl rand -base64 36 | tr -d '\n=/+' | head -c 48"
ensure_secret AUTHENTIK_SECRET_KEY "openssl rand -base64 60 | tr -d '\n'"

# VW_SSO_ONLY : pas un secret d'entropie mais meme probleme que ci-dessus -- un
# .env cree avant l'ajout de cette variable a .env.example ne la contient pas
# du tout. Defaut sur false (jamais true automatiquement : ne jamais couper le
# fallback master password sans validation explicite d'un login SSO reussi).
ensure_secret VW_SSO_ONLY "echo false"

mkdir -p vw-data ../02_caddy/logs   # deploy/02_caddy/logs, PAS deploy/03_docker/caddy/logs (deploy/02_caddy/ est un sibling)

# --- 7. Resolution locale (hote non domain-joined, idempotent) ---------------------
for h in "$SPN_HOSTNAME" "$AUTH_HOSTNAME"; do
    if ! grep -q "$h" /etc/hosts; then
        echo "127.0.0.1 $h" | sudo tee -a /etc/hosts >/dev/null
        ok "/etc/hosts mis a jour pour $h"
    else
        warn "/etc/hosts contient deja une entree pour $h, non modifiee"
    fi
done

# --- 8. Deploiement + gates ----------------------------------------------------------
# Down avant up : la topologie (services/reseaux) peut avoir change entre deux
# executions de ce script (ex. ajout d'Authentik et de ses reseaux internal=true) --
# repartir d'une ancienne installation encore levee peut laisser des conteneurs/
# reseaux perimes en conflit. --remove-orphans nettoie les services retires du
# compose. Ne touche jamais aux volumes nommes (pas de -v/--volumes) : la base
# Authentik (authentik-database) et vw-data (bind mount) sont preservees.
info "Arret de l'ancienne installation (si presente, sans toucher aux volumes/donnees)"
docker compose down --remove-orphans || warn "docker compose down : rien a arreter ou erreur mineure -- poursuite"

info "Build et demarrage de la stack"
docker compose up -d --build
ok "Stack demarree"

sleep 3
if ! openssl s_client -connect "$SPN_HOSTNAME:443" -servername "$SPN_HOSTNAME" \
        -CAfile adcs-root.crt </dev/null 2>&1 | grep -q "Verify return code: 0"; then
    fail "Gate TLS echoue (Verify return code != 0) -- chaine non validee jusqu'a la racine AD CS"
fi
ok "Gate TLS : chaine validee jusqu'a la racine AD CS"

if ! docker exec vaultwarden curl -fsS "https://$SPN_HOSTNAME/alive" >/dev/null; then
    fail "Gate interne echoue -- le conteneur vaultwarden ne joint pas Caddy en HTTPS (verifier l'alias reseau backend)"
fi
ok "Gate interne : vaultwarden fait confiance a la chaine"

# Authentik (server+worker+postgresql+redis) met nettement plus longtemps que
# Caddy/Vaultwarden a devenir pret au premier demarrage (migrations DB) -- gate
# souple (avertit, ne bloque pas la fin du script) plutot qu'une attente fixe
# arbitraire. Un code HTTP quelconque (meme une redirection vers le setup
# initial) confirme que Caddy joint bien authentik-server ; une absence totale
# de reponse ne l'est pas.
info "Verification qu'Authentik repond (peut prendre 1-2 minutes au premier demarrage)"
attempt=1
authentik_ok=0
while (( attempt <= 10 )); do
    code=$(curl -sk -o /dev/null -w '%{http_code}' "https://$AUTH_HOSTNAME/" 2>/dev/null || echo 000)
    if [ "$code" != "000" ]; then
        authentik_ok=1
        break
    fi
    sleep 6
    attempt=$((attempt+1))
done
if [ "$authentik_ok" = "1" ]; then
    ok "Authentik repond via Caddy (HTTP $code) -- normal si ce n'est pas 200 avant le setup initial"
else
    warn "Authentik ne repond toujours pas apres 60s -- verifier 'docker compose logs authentik-server authentik-worker'"
    warn "  (migrations DB en cours au premier demarrage : patienter puis retester manuellement)"
fi

echo ""
ok "Phase 1 terminee et validee."
warn "Purger le PFX et le mot de passe cote DC si ce n'est pas deja fait :"
warn "  Remove-Item C:\\vault-new.pfx, C:\\vault-new.pfxpass.txt, C:\\vault-new.cer, C:\\vault-new.csr, C:\\vault-new.inf, C:\\adcs-root.cer -Force"
