#!/usr/bin/env bash
# =============================================================================
# render-blueprint.sh
# Substitue les placeholders de kerberos-sso-blueprint.yaml (<REALM>, <DC_IP>,
# <DOMAIN_DNS>, <CLIENT_SUBNETS_PYLIST>) depuis deploy/environment.env et
# produit kerberos-sso-blueprint.rendered.yaml -- c'est CE fichier rendu qu'il
# faut importer dans Authentik, jamais le template source.
# -----------------------------------------------------------------------------
# Usage :
#   deploy/authentik/render-blueprint.sh
#   deploy/authentik/render-blueprint.sh /chemin/vers/environment.env
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ENV_FILE="${1:-$REPO_ROOT/deploy/environment.env}"
TEMPLATE="$SCRIPT_DIR/kerberos-sso-blueprint.yaml"
OUT="$SCRIPT_DIR/kerberos-sso-blueprint.rendered.yaml"

info(){ echo -e "\033[36m[INFO]\033[0m $*"; }
ok(){   echo -e "\033[32m[ OK ]\033[0m $*"; }
fail(){ echo -e "\033[31m[FAIL]\033[0m $*" >&2; exit 1; }

[ -f "$ENV_FILE" ] || fail "Config introuvable : $ENV_FILE -- copier deploy/environment.env.example vers deploy/environment.env et le renseigner d'abord."

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

: "${REALM:?REALM manquant dans $ENV_FILE}"
: "${DC_IP:?DC_IP manquant dans $ENV_FILE}"
: "${DOMAIN_DNS:?DOMAIN_DNS manquant dans $ENV_FILE}"
: "${CLIENT_SUBNETS:?CLIENT_SUBNETS manquant dans $ENV_FILE}"

if [ "$CA_ROOT_THUMBPRINT" = "CHANGE_ME_SHA1_THUMBPRINT" ] 2>/dev/null; then
    fail "$ENV_FILE n'a pas ete renseigne (placeholders encore presents) -- editer le fichier avant de rendre le blueprint."
fi

# CSV "192.168.100.0/24,10.20.30.0/24" -> liste Python ["192.168.100.0/24", "10.20.30.0/24"]
IFS=',' read -ra _subnets <<< "$CLIENT_SUBNETS"
pylist='['
first=1
for cidr in "${_subnets[@]}"; do
    cidr="$(echo "$cidr" | xargs)"   # trim
    [ -n "$cidr" ] || continue
    if [ "$first" -eq 1 ]; then first=0; else pylist+=', '; fi
    pylist+="\"$cidr\""
done
pylist+=']'
info "Reseaux clients rendus : $pylist"

sed \
    -e "s#<REALM>#${REALM}#g" \
    -e "s#<DC_IP>#${DC_IP}#g" \
    -e "s#<DOMAIN_DNS>#${DOMAIN_DNS}#g" \
    -e "s#<CLIENT_SUBNETS_PYLIST>#${pylist}#g" \
    "$TEMPLATE" > "$OUT"

ok "Blueprint rendu : $OUT"
echo "    docker exec -i authentik-server ak import_blueprint < \"$OUT\""
