# Phase 5 — Analyse de risque : Trusted Device Encryption (TDE)

## Principe

Le master password est saisi **une seule fois**, à l'onboarding, sur chaque device. OIDCWarden chiffre la clé de compte avec une **Device Key** générée localement et échangée via un mécanisme d'approbation (Account Recovery de l'Organization). Les logins suivants sur un device déjà approuvé ne redemandent **jamais** le master password.

Prérequis cumulatifs (à ne pas découpler) :
- `SSO_ORGANIZATIONS_ENABLED=true` + mapping groupe AD → Organization (invitation automatique).
- Organization avec policy **Single Organization** (empêche un membre de rejoindre une autre org qui contournerait la contrainte TDE) et policy **Account Recovery Administration** avec auto-enrollment (permet la levée d'un device perdu sans re-création de coffre).

## Ordre strict d'exécution (Phase 5)

1. **Backup complet préalable** : dump PostgreSQL/SQLite selon le backend + archive `/data` + snapshot si virtualisé. Gate : restauration testée à blanc (`pg_restore --list` au minimum).
2. Version OIDCWarden épinglée : `v2026.6.4-1` (vérifiée sur Docker Hub à la rédaction — **revérifier** avant build, et lire les migrations si la base du fork a dépassé 1.36.x).
3. `docker compose build && docker compose up -d` avec `SSO_ONLY=false` (déjà le défaut dans `docker-compose.yml`). Gate : login SSO d'un compte test, flux complet sans régression, compte visible dans `/admin`.
4. Créer l'Organization cible, activer **Single Organization** puis **Account Recovery Administration** (auto-enrollment). Mapper le groupe AD via les claims groupes Authentik → `SSO_ORGANIZATIONS_*`.
5. Gate TDE : nouvel utilisateur test → onboarding (master password défini une fois) → membre de l'org → policies visibles → login suivant : option "Se souvenir de cet appareil" / device approval présente → login N+2 : **aucun master password demandé**.
6. **Break-glass AVANT `SSO_ONLY=true`** : compte local hors SSO (email hors domaine dédié, ex. `breakglass@vaultwardensso.local` non provisionné par la source LDAP/Kerberos), master password fort en coffre physique/scellé, **exclu de l'organization SSO** (sinon TDE l'engloberait). Tester le login break-glass avec `SSO_ONLY=true` actif — il doit passer. Si l'architecture du fork ne le permet pas nativement (compte local + `SSO_ONLY=true` peuvent être mutuellement exclusifs selon la version), documenter la procédure de bascule `SSO_ONLY=false` via `.env` + `docker compose up -d` comme break-glass de niveau 2.
7. Gate final : poste domaine vierge → ouverture session Windows → navigateur → coffre déverrouillé. Saisies utilisateur attendues : email (1ʳᵉ fois), master password (onboarding uniquement), approbation device. Ensuite : **zéro saisie**.

## Analyse de risque (à reporter dans le runbook d'exploitation)

| Risque | Détail | Compensation obligatoire |
|---|---|---|
| **Le poste devient le périmètre du coffre** | La Device Key réside sur le poste (profil utilisateur local). Un poste compromis = coffre déchiffrable sans master password. | BitLocker via GPO sur le parc concerné, verrouillage de session automatique (GPO, ≤ 10 min), interdiction TDE sur postes partagés/non chiffrés (politique à documenter, pas techniquement bloquée par OIDCWarden lui-même). |
| **Account Recovery = escrow de clé** | Les admins de l'org peuvent réinitialiser l'accès d'un membre (clé de compte mise en escrow via la clé publique de l'org). | Restreindre le rôle admin org au strict minimum de personnes ; journaliser tout usage de recovery (events OIDCWarden → SIEM, cf. `docs/03_supervision_siem.md`) ; procédure à 4 yeux pour toute recovery. |
| **Compte AD compromis + poste de la victime = coffre ouvert sans autre facteur** | Le SPNEGO authentifie via le TGT de session ; combiné à un device déjà approuvé, aucune resaisie n'intervient — donc aucun second facteur naturel. | MFA côté Authentik reste au backlog **prioritaire**. Le SPNEGO ne doit pas devenir un contournement du MFA prévu : arbitrage à faire (MFA à l'enrôlement device uniquement, ou MFA obligatoire hors périmètre intranet). Tant que ce backlog n'est pas traité, documenter le risque résiduel accepté explicitement (signature du risk owner). |
| **Révocation incomplète** | Désactivation du compte AD → SPNEGO KO + refresh token KO côté Authentik/OIDCWarden. Mais un device déjà déverrouillé conserve les données en clair localement (cache applicatif, mémoire, éventuellement disque si le poste n'est pas chiffré). | La procédure de départ (matrice de déprovisionnement, Phase 6) doit inclure explicitement : révocation du device dans `/admin` **et** wipe/reimage du poste, pas seulement la désactivation AD. |

## Ce que ce document ne couvre pas

- Le choix technique définitif entre `SSO_ONLY=false` permanent (SSO recommandé, password toujours possible) vs `SSO_ONLY=true` (SSO obligatoire, break-glass seul recours) relève d'une décision opérationnelle du risk owner, à documenter dans le runbook final avec justification.
- Le MFA Authentik (mentionné comme backlog prioritaire ci-dessus) fait l'objet d'un arbitrage séparé, hors périmètre de cette phase.
