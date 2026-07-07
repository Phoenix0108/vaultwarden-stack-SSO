# =============================================================================
# Image Vaultwarden dérivée :
#   - épingle la version (reproductibilité, pas de :latest qui casserait les migrations SSO)
#   - embarque la CA racine AD CS pour que le conteneur fasse confiance à AD FS (id_token discovery)
# -----------------------------------------------------------------------------
# Prérequis : adcs-root.crt (PEM) présent dans ce répertoire, empreinte SHA-1 vérifiée
#   openssl x509 -inform der -in adcs-root.cer -out adcs-root.crt
#   openssl x509 -in adcs-root.crt -noout -fingerprint -sha1   # == Thumbprint AD CS
# =============================================================================
FROM vaultwarden/server:1.36.0

# CA interne : on AJOUTE la confiance à notre AC, on ne désactive JAMAIS la vérification TLS
COPY adcs-root.crt /usr/local/share/ca-certificates/adcs-root.crt
RUN update-ca-certificates
