#!/usr/bin/env bash
# =============================================================================
# vw-egress-fw.sh — Allow-list egress du conteneur Vaultwarden (moindre privilège réseau)
# -----------------------------------------------------------------------------
# Applique dans la chaîne DOCKER-USER (évaluée AVANT les règles Docker) :
#   - retour des connexions établies
#   - autorise UNIQUEMENT VW_EGRESS -> ADFS_IP:443/tcp
#   - LOG + DROP de toute autre sortie (détection d'anomalie / exfiltration)
# Idempotent (iptables -C ... || iptables -I ...) : pas de doublon au restart Docker.
# À installer sous /usr/local/sbin/ et invoquer via l'unité systemd vw-egress-fw.service.
# =============================================================================
set -euo pipefail
export PATH="$PATH:/usr/sbin:/sbin"

VW_EGRESS="172.31.9.0/29"      # subnet du réseau adfs_egress
ADFS_IP="192.168.100.93"       # IP du serveur AD FS
LOG_PREFIX="VW-EGRESS-DROP: "

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
add_rule 2 -s "$VW_EGRESS" -d "$ADFS_IP" -p tcp --dport 443 -j RETURN
add_rule 3 -s "$VW_EGRESS" -j LOG --log-prefix "$LOG_PREFIX" --log-level 4
add_rule 4 -s "$VW_EGRESS" -j DROP

echo "[vw-egress-fw] Règles appliquées :"
iptables -L DOCKER-USER -n -v --line-numbers
