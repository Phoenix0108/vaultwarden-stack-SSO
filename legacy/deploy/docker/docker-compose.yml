# =============================================================================
# Vaultwarden + Caddy - déploiement durci (Security by Design)
# -----------------------------------------------------------------------------
# Architecture réseau :
#   - frontend   : Caddy <-> extérieur (443/80)
#   - backend    : internal=true -> Vaultwarden joignable UNIQUEMENT via Caddy
#   - adfs_egress: bridge dédié, seule sortie autorisée = AD FS:443 (filtrée DOCKER-USER)
# Durcissement conteneur : no-new-privileges, cap_drop ALL, read_only + tmpfs.
# Secret : ADMIN_TOKEN et SSO_CLIENT_SECRET via .env (hors dépôt versionné).
# =============================================================================
services:
  vaultwarden:
    build:
      context: ./            # image dérivée : Dockerfile embarque la CA racine AD CS + épingle la version
    container_name: vaultwarden
    restart: unless-stopped
    environment:
      DOMAIN: "https://vault.vaultwardensso.local/"
      SIGNUPS_ALLOWED: "false"
      ADMIN_TOKEN: "${VW_ADMIN_TOKEN}"          # depuis .env
      # --- SSO OIDC (voir vaultwarden.env.example pour le détail commenté) ---
      SSO_ENABLED: "true"
      SSO_ONLY: "true"                          # break-glass à prévoir ; "false" en phase de test
      SSO_CLIENT_ID: "${VW_SSO_CLIENT_ID}"
      SSO_CLIENT_SECRET: "${VW_SSO_CLIENT_SECRET}"   # cible : SSO_CLIENT_SECRET_FILE + secret Docker
      SSO_AUTHORITY: "https://SRVADTEST.vaultwardensso.local/adfs"   # CASSE EXACTE de l'issuer
      SSO_SCOPES: "email profile offline_access"     # openid ajouté automatiquement
      SSO_ALLOW_UNKNOWN_EMAIL_VERIFICATION: "true"   # AD FS n'émet pas email_verified
      SSO_PKCE: "true"
      # --- Journalisation : régime NORMAL (pas de jetons en clair) ---
      LOG_LEVEL: "info"
      # SSO_DEBUG_TOKENS: "true"   # <-- N'ACTIVER QUE pour un diagnostic ponctuel, puis retirer + purger logs
    volumes:
      - ./vw-data:/data/
    networks:
      - backend
      - adfs_egress
    security_opt:
      - "no-new-privileges:true"
    cap_drop:
      - ALL                          # Vaultwarden n'a besoin d'aucune capability
    read_only: true                  # rootfs immuable ...
    tmpfs:
      - /tmp                         # ... /data (volume) reste le seul point d'écriture
    extra_hosts:
      - "srvadtest.vaultwardensso.local:192.168.100.93"   # résolution statique de l'IdP (dépendance critique)
    deploy:
      resources:
        limits:                      # anti-DoS : borne l'impact d'une saturation
          memory: 512M
          cpus: "1.0"
    healthcheck:
      test: ["CMD", "sh", "-c", "wget -qO- http://127.0.0.1/alive || exit 1"]
      interval: 60s
      timeout: 5s
      retries: 3

  caddy:
    image: caddy:2-alpine
    container_name: caddy
    restart: unless-stopped
    ports:
      - "443:443"
      - "443:443/udp"                # HTTP/3
      - "80:80"                      # redirect HTTP -> HTTPS
    volumes:
      - ./caddy/Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy-data:/data
      - caddy-config:/config
      - ./caddy/logs:/var/log/caddy
    networks:
      - frontend
      - backend
    security_opt:
      - "no-new-privileges:true"
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE             # nécessaire pour écouter 80/443
    deploy:
      resources:
        limits:
          memory: 256M
          cpus: "0.5"

networks:
  frontend: {}
  backend:
    internal: true                   # Vaultwarden reste injoignable hors Caddy (aucun egress WAN)
  adfs_egress:
    driver: bridge
    driver_opts:
      com.docker.network.bridge.name: br-adfs   # nom d'IF stable pour le pare-feu hôte
    ipam:
      config:
        - subnet: 172.31.9.0/29      # /29 = 6 IP utiles : surface minimale

volumes:
  caddy-data: {}
  caddy-config: {}
