#!/usr/bin/env bash
# =============================================================================
# vw-egress-fw.sh — Allow-list egress du conteneur Vaultwarden (moindre privilège réseau)
# -----------------------------------------------------------------------------
# Applique dans la chaîne DOCKER-USER (évaluée AVANT les règles Docker) :
#   - retour des connexions établies
#   - autorise UNIQUEMENT authentik_egress -> AUTHENTIK_IP:443/tcp (back-channel OIDC)
#   - LOG + DROP de toute autre sortie (détection d'anomalie / exfiltration)
# Idempotent (iptables -C ... || iptables -I ...) : pas de doublon au restart Docker.
# À installer sous /usr/local/sbin/ et invoquer via l'unité systemd vw-egress-fw.service.
# =============================================================================
set -euo pipefail
export PATH="$PATH:/usr/sbin:/sbin"

VW_EGRESS="172.31.10.0/29"     # subnet du réseau authentik_egress
AUTHENTIK_IP="__AUTHENTIK_IP__"   # IP réelle d'auth.vaultwardensso.local — À RENSEIGNER avant activation
LOG_PREFIX="VW-EGRESS-DROP: "

if [ "$AUTHENTIK_IP" = "__AUTHENTIK_IP__" ]; then
  echo "[vw-egress-fw] AUTHENTIK_IP non renseignee (placeholder toujours present). Abandon." >&2
  exit 1
fi

# La chaîne DOCKER-USER est créée par Docker ; échouer proprement si absente
if ! iptables -L DOCKER-USER -n >/dev/null 2>&1; then
  echo "[vw-egress-fw] Chaîne DOCKER-USER absente (Docker démarré ?). Abandon." >&2
  exit 1
fi

add_rule() {
  # $1 = numéro d'insertion, $@ = spec de règle
  local pos="$1"; shift
  if ! iptables -C DOCKER-USER "$@" 2>/dev/null; then
    iptables -I DOCKER-USER "$pos" "$@"
  fi
}

# Ordre important : insertions en tête (les plus prioritaires en dernier inséré)
add_rule 1 -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
add_rule 2 -s "$VW_EGRESS" -d "$AUTHENTIK_IP" -p tcp --dport 443 -j RETURN
add_rule 3 -s "$VW_EGRESS" -j LOG --log-prefix "$LOG_PREFIX" --log-level 4
add_rule 4 -s "$VW_EGRESS" -j DROP

echo "[vw-egress-fw] Règles appliquées :"
iptables -L DOCKER-USER -n -v --line-numbers
