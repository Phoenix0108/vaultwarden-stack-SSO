# =============================================================================
# .env — Secrets & identifiants (NE JAMAIS versionner le .env réel)
# Copier en .env, renseigner, chmod 600, propriétaire root.
# .gitignore DOIT contenir : .env
# =============================================================================

# Token d'accès à la console /admin (générer avec : docker run --rm vaultwarden/server:1.36.0 /vaultwarden hash)
# Utiliser un HASH Argon2, pas un token en clair.
VW_ADMIN_TOKEN=

# Identifiant client OIDC = Identifier de la Server Application AD FS
VW_SSO_CLIENT_ID=d2d6941a-d29e-4efc-8f1d-2d0058ad257d

# Secret client OIDC (récupéré via Set-AdfsServerApplication -ResetClientSecret -PassThru)
# Cible durcissement : remplacer par SSO_CLIENT_SECRET_FILE monté en secret Docker
VW_SSO_CLIENT_SECRET=
