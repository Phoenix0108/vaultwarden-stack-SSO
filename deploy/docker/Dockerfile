# =============================================================================
# Image OIDCWarden derivee (Phase 5 - bascule depuis vaultwarden/server:1.36.0) :
#   - fork Timshel/OIDCWarden (iso-schema Vaultwarden, ajoute SSO_TRUSTED_DEVICE_ENCRYPTION)
#   - epingle la version (reproductibilite, pas de :latest)
#   - embarque la CA racine AD CS pour que le conteneur fasse confiance a la
#     chaine interne ET au back-channel OIDC Authentik (discovery/token/jwks)
# -----------------------------------------------------------------------------
# Version epinglee au moment de la redaction : v2026.6.4-1 (verifiee sur
# hub.docker.com/r/timshel/oidcwarden/tags). REVERIFIER avant tout build : si
# la base du fork a avance au-dela de 1.36.x, lire les migrations embarquees
# AVANT de basculer (cf. deploy/docs/02_risk_analysis_tde.md).
#
# Prerequis : adcs-root.crt (PEM) present dans ce repertoire, empreinte SHA-1
# verifiee AVANT le build (thumbprint AD CS = 473BAAC9189D52715E3E73CED9BEC691293BED10) :
#   openssl x509 -inform der -in adcs-root.cer -out adcs-root.crt
#   openssl x509 -in adcs-root.crt -noout -fingerprint -sha1
# adcs-root.crt est exclu du depot (.gitignore) : a placer manuellement avant build.
# =============================================================================
FROM timshel/oidcwarden:v2026.6.4-1

# CA interne : on AJOUTE la confiance a notre AC, on ne desactive JAMAIS la verification TLS
COPY adcs-root.crt /usr/local/share/ca-certificates/adcs-root.crt
RUN update-ca-certificates
