#!/usr/bin/env bash
# =============================================================================
# install-vault-cert.sh
# Recupere le certificat + la racine AD CS generes par New-VaultCertDC.ps1 sur
# le DC, les convertit, les assemble, les installe dans le depot, deploie
# Caddy/Vaultwarden et valide les gates. A executer depuis n'importe ou dans
# le depot cloné, sur l'hote Docker (hors domaine AD).
# -----------------------------------------------------------------------------
# Resilient : retries avec backoff sur le transfert SMB (reseau lab peu fiable
# possible) ; detection automatique du fallback openssl -legacy vs -provider ;
# verification a chaque etape (SAN, empreinte SHA-1, gates TLS) avec arret net
# et message diagnostique si un controle echoue -- jamais de contournement
# silencieux ; nettoyage systematique des fichiers secrets transitoires meme
# en cas d'echec (trap EXIT) ; idempotent sur .env et /etc/hosts (ne les
# ecrase pas s'ils existent deja).
# -----------------------------------------------------------------------------
# Menace couverte : cle privee et mot de passe PFX jamais loggues ; ADMIN_TOKEN
# genere avec suffisamment d'entropie (openssl rand) si .env n'existe pas
# encore ; verification TLS jamais desactivee (-CAfile, jamais -k/--insecure).
# Privilege minimal : sudo requis uniquement pour install/tee vers des chemins
# root-owned deja definis par docker-compose.yml, rien d'autre.
# Residuel : si SMB_PASSWORD est fourni en variable d'environnement, il reste
# brievement visible dans la table des process (ps) le temps de l'appel
# smbclient -- preferer la saisie interactive si le contexte le permet.
# =============================================================================
set -euo pipefail

DC_IP="${DC_IP:-192.168.100.76}"
DC_USER="${DC_USER:-VAULTWARDENSSO\\Administrator}"
SPN_HOSTNAME="${SPN_HOSTNAME:-vault.vaultwardensso.local}"
ROOT_THUMBPRINT="${ROOT_THUMBPRINT:-473BAAC9189D52715E3E73CED9BEC691293BED10}"
SMB_RETRIES="${SMB_RETRIES:-3}"
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"

info(){ echo -e "\033[36m[INFO]\033[0m $*"; }
ok(){   echo -e "\033[32m[ OK ]\033[0m $*"; }
warn(){ echo -e "\033[33m[WARN]\033[0m $*"; }
fail(){ echo -e "\033[31m[FAIL]\033[0m $*" >&2; exit 1; }

TMP_FILES=(vault-new.pfx vault-new.pfxpass.txt vault-new.cer vault-new.pem adcs-root.cer adcs-root.pem)
cleanup() {
    info "Nettoyage des fichiers transitoires locaux"
    ( cd "$REPO_ROOT" && rm -f "${TMP_FILES[@]}" ) 2>/dev/null || true
}
trap cleanup EXIT

cd "$REPO_ROOT"

for bin in smbclient openssl docker; do
    command -v "$bin" >/dev/null || fail "$bin absent (installer avant de continuer)"
done

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
if ! openssl x509 -in vault-new.pem -noout -ext subjectAltName | grep -q "$SPN_HOSTNAME"; then
    fail "SAN du certificat ne contient pas $SPN_HOSTNAME -- mauvais certificat, ne pas continuer."
fi
ok "SAN verifie : $SPN_HOSTNAME present"

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
sudo install -o root -g root -m 644 vault.crt     deploy/caddy/certs/vault.crt
sudo install -o root -g root -m 600 vault.key     deploy/caddy/certs/vault.key
sudo install -o root -g root -m 644 adcs-root.pem deploy/docker/adcs-root.crt
rm -f vault.crt vault.key
ok "Chaine installee dans deploy/caddy/certs et deploy/docker"

# --- 6. Secrets applicatifs (.env, idempotent : jamais ecrase s'il existe) ---------
cd deploy/docker
if [ ! -f .env ]; then
    info "Creation de .env (nouveau token admin genere, entropie suffisante)"
    cp .env.example .env
    chmod 600 .env
    token=$(openssl rand -base64 48)
    sed -i "s#VW_ADMIN_TOKEN=.*#VW_ADMIN_TOKEN=${token}#" .env
    ok ".env cree avec VW_ADMIN_TOKEN genere"
else
    warn ".env deja present, non modifie (idempotent) -- verifier VW_ADMIN_TOKEN manuellement si besoin"
fi

mkdir -p vw-data caddy/logs

# --- 7. Resolution locale (hote non domain-joined, idempotent) ---------------------
if ! grep -q "$SPN_HOSTNAME" /etc/hosts; then
    echo "127.0.0.1 $SPN_HOSTNAME" | sudo tee -a /etc/hosts >/dev/null
    ok "/etc/hosts mis a jour pour $SPN_HOSTNAME"
else
    warn "/etc/hosts contient deja une entree pour $SPN_HOSTNAME, non modifiee"
fi

# --- 8. Deploiement + gates ----------------------------------------------------------
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

echo ""
ok "Phase 1 terminee et validee."
warn "Purger le PFX et le mot de passe cote DC si ce n'est pas deja fait :"
warn "  Remove-Item C:\\vault-new.pfx, C:\\vault-new.pfxpass.txt, C:\\vault-new.cer, C:\\vault-new.csr, C:\\vault-new.inf, C:\\adcs-root.cer -Force"
