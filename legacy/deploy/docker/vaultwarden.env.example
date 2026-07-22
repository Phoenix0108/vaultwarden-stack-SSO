# =============================================================================
# vaultwarden.env — reference des variables SSO (documentation)
# Les valeurs sensibles vont dans .env (VW_ADMIN_TOKEN, VW_SSO_CLIENT_SECRET).
# =============================================================================

# --- Base ---
DOMAIN=https://vault.vaultwardensso.local/
SIGNUPS_ALLOWED=false            # ATTENTION : le SSO contourne ce flag (provisionnement JIT)

# --- SSO OIDC ---
SSO_ENABLED=true
SSO_ONLY=true                    # true = annuaire autoritaire (PREVOIR un compte break-glass hors SSO)
SSO_CLIENT_ID=d2d6941a-d29e-4efc-8f1d-2d0058ad257d
# SSO_CLIENT_SECRET : via .env (VW_SSO_CLIENT_SECRET) ; cible = SSO_CLIENT_SECRET_FILE + secret Docker
SSO_AUTHORITY=https://SRVADTEST.vaultwardensso.local/adfs   # CASSE EXACTE de l'issuer du discovery
SSO_SCOPES=email profile offline_access                     # openid ajoute automatiquement (ne pas dupliquer)
SSO_PKCE=true                                               # durcit contre l'interception du code d'autorisation
SSO_ALLOW_UNKNOWN_EMAIL_VERIFICATION=true                   # AD FS n'emet pas email_verified booleen

# Ne PAS activer en continu (jetons en clair sur disque) :
# SSO_DEBUG_TOKENS=true

# --- Session / revocation ---
# Laisser SSO_AUTH_ONLY_NOT_SESSION NON defini (= false) : la session reste liee au jeton,
# donc un compte AD desactive perd sa session au prochain refresh echoue.

# --- Journalisation ---
LOG_LEVEL=info                   # 'info,vaultwarden::sso=debug' UNIQUEMENT pour un diagnostic ponctuel
