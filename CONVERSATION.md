# Conversation — Sécurisation du starter Rust + Axum + PostgreSQL

**Date :** 10 novembre 2026  
**Projet :** `rust-pg-vanilla-starter` — starter d'authentification Rust + Axum + PostgreSQL  

---

## Objectif

Partir d'un squelette d'authentification basique et l'améliorer avec :

1. **Gestion des utilisateurs** — création, modification, désactivation, attribution de rôle
2. **Gestion des appareils** — enregistrement et validation par un admin
3. **Contrôle des connexions** — login bloqué tant que l'appareil n'est pas approuvé
4. **Gestion des sessions** — expiration, déconnexion, révocation
5. **Journal d'audit** — historique complet des connexions, appareils, actions admin

**Technologies :** Rust + Axum 0.8, PostgreSQL, SQLx, Argon2id, Vanilla JS, HTML5/CSS3

---

## Fichiers créés ou modifiés

### `migrations/0001_init.sql` — commenté

Schéma de base : tables `users`, `devices`, `sessions`.  
Principes clés documentés :
- Les tokens sont stockés en SHA-256 (jamais le token brut)
- Les mots de passe sont hashés en Argon2id
- Les cookies sont `HttpOnly` + `SameSite=Lax`

### `migrations/0002_security.sql` — créé

```sql
ALTER TABLE devices
    ADD COLUMN IF NOT EXISTS approved    BOOLEAN     NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS approved_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS approved_by UUID        REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS name        TEXT,
    ADD COLUMN IF NOT EXISTS user_agent  TEXT,
    ADD COLUMN IF NOT EXISTS ip_address  TEXT;

-- Rétrocompatibilité : les appareils existants sont automatiquement approuvés
UPDATE devices SET approved = TRUE WHERE approved = FALSE;

CREATE TABLE IF NOT EXISTS audit_logs (
    id          UUID        PRIMARY KEY,
    user_id     UUID        REFERENCES users(id) ON DELETE SET NULL,
    action      TEXT        NOT NULL,
    target_id   UUID,
    target_type TEXT,
    ip_address  TEXT,
    user_agent  TEXT,
    details     JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS audit_logs_user_id_idx    ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS audit_logs_created_at_idx ON audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS audit_logs_action_idx     ON audit_logs(action);
```

### `Cargo.toml` — modifié

Ajout de la feature `json` à SQLx pour lier des valeurs `serde_json::Value` aux colonnes JSONB :

```toml
sqlx = { version = "0.8", features = [
    "runtime-tokio-rustls", "postgres", "uuid",
    "chrono", "json", "migrate", "macros"
] }
```

### `src/state.rs` — créé

```rust
use sqlx::PgPool;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
}
```

### `src/auth.rs` — créé (~170 lignes)

Fonctions utilitaires de sécurité et d'authentification :

| Fonction | Rôle |
|---|---|
| `random_token()` | 32 octets OsRng → hex (256 bits) |
| `token_hash(token)` | SHA-256 → hex |
| `cookie(name, value, max_age)` | Cookie HttpOnly + SameSite=Lax |
| `clear_cookie(name)` | Cookie Max-Age=0 (suppression) |
| `get_cookie(headers, name)` | Parse l'en-tête Cookie |
| `get_ip(headers)` | Première IP de X-Forwarded-For |
| `get_ua(headers)` | En-tête User-Agent |
| `error_response(status, msg)` | JSON `{"message": "..."}` |
| `auth_session(db, headers)` | Valide le cookie app_session en DB |
| `auth_admin(db, headers)` | auth_session + vérifie role=="admin" |
| `audit_log(...)` | INSERT dans audit_logs (fire-and-forget) |

**Struct `AuthUser`** (retournée par `auth_session`) :
```rust
pub struct AuthUser {
    pub id: Uuid,
    pub email: String,
    pub role: String,
    pub session_id: Uuid,
}
```

### `src/handlers.rs` — créé (~480 lignes)

**14 endpoints implémentés :**

| Méthode | Route | Description |
|---|---|---|
| GET | `/api/health` | Statut du serveur |
| POST | `/api/register` | Créer un compte (1er user = admin) |
| POST | `/api/login` | Ouvrir une session |
| GET | `/api/me` | Profil de l'utilisateur connecté |
| POST | `/api/logout` | Fermer la session courante |
| POST | `/api/logout-all` | Fermer toutes ses sessions |
| GET | `/api/sessions` | Lister ses sessions actives |
| POST | `/api/sessions/{id}/revoke` | Révoquer une session |
| GET | `/api/admin/users` | Lister tous les utilisateurs |
| PATCH | `/api/admin/users/{id}` | Modifier un utilisateur |
| GET | `/api/admin/devices` | Lister tous les appareils |
| POST | `/api/admin/devices/{id}/approve` | Approuver un appareil |
| POST | `/api/admin/devices/{id}/revoke` | Révoquer un appareil |
| GET | `/api/admin/logs` | Journal d'audit paginé |

**Flux de login (le plus complexe) :**

```
1. Chercher l'utilisateur par email (email introuvable → même erreur que mauvais mdp)
2. Vérifier active=true, valider le mot de passe Argon2id → audit login_failed si échec
3. Lire le cookie app_device → SHA-256 → chercher en DB
4. Selon l'appareil trouvé :
   - Existant → vérifier propriétaire, revoked, approved → update last_seen_at
   - Nouveau   → create_device() → 403 si en attente, OK si approuvé
5. INSERT session avec expiration 7 jours
6. Répondre avec cookie app_session (7j) + app_device si nouvel appareil
```

### `src/main.rs` — réécrit

Router Axum 0.8 avec toutes les routes et commentaires d'extension.

> ⚠️ **Syntaxe Axum 0.8** : paramètres de route avec `{id}` et **non** `:id`

### `static/index.html` — réécrit

SPA à 4 sections :
- `#loading` — spinner d'initialisation
- `#login-section` — formulaire de connexion
- `#dashboard-section` — sessions + déconnexion
- `#admin-section` — 3 onglets : Appareils / Utilisateurs / Journaux

### `static/js/app.js` — réécrit (~270 lignes)

| Fonction | Rôle |
|---|---|
| `api(path, options)` | Wrapper fetch, lève une erreur avec `.status` |
| `el(tag, attrs, ...children)` | Constructeur DOM déclaratif |
| `statusBadge(approved, revoked)` | Badge coloré de statut |
| `makeTable(cols, rows)` | Génère un `<table>` depuis des tableaux |
| `showLogin()` / `showApp(user)` | Gestion de la visibilité des sections |
| `loadSessions()` | Charge les sessions actives |
| `loadDevices()` | Charge les appareils (admin) |
| `loadUsers()` | Charge les utilisateurs (admin) |
| `loadLogs(reset)` | Charge le journal avec pagination |

### `static/css/style.css` — réécrit

Variables CSS, composants `.card`, `.tabs`, `.badge-*`, `.btn-*`, `.tbl-wrap`.

---

## Problèmes rencontrés et solutions

### 1. Panique au démarrage — syntaxe Axum 0.8

**Symptôme :**
```
thread 'main' panicked at 'Path segments must not start with ':'
```

**Cause :** Axum 0.8 a changé la syntaxe des paramètres de route de `:id` à `{id}`.

**Solution :** Remplacer tous les `:id` par `{id}` dans `main.rs`.

---

### 2. Ancien processus sur le port 3000

**Symptôme :** `curl` retournait des réponses de l'ancienne version alors que le code avait changé.

**Solution :** `pkill -f scores-billard` avant de relancer.

---

### 3. Bug `disabled` en JavaScript

**Symptôme :** `el("button", { disabled: false })` désactivait quand même le bouton.

**Cause :** `setAttribute("disabled", "")` active l'attribut quelle que soit la valeur. La présence de l'attribut suffit.

**Solution :** Dans `el()`, ne pas appeler `setAttribute` si la valeur est `false`, `null` ou `undefined`.

---

## Décisions d'architecture

### Bootstrap admin (oeuf ou poule ?)

Le premier utilisateur inscrit obtient automatiquement `role="admin"` (via `SELECT COUNT(*) FROM users` = 0). Ses appareils sont auto-approuvés. Il peut ensuite approuver les appareils des autres.

### Fraîcheur du rôle

La requête `auth_session()` fait un JOIN sur `users.role` à chaque requête. Un changement de rôle prend effet immédiatement sans invalider les sessions existantes.

### Anti-verrouillage admin

`admin_update_user()` refuse de désactiver son propre compte (`target_id == admin.id`).

### Protection IDOR sur les sessions

```sql
DELETE FROM sessions WHERE id = $1 AND user_id = $2
```
Si la session appartient à quelqu'un d'autre, `rows_affected() == 0` → 404 (sans révéler l'existence).

### Prévention d'énumération des emails

Même message d'erreur si l'email n'existe pas ou si le mot de passe est incorrect.

---

## Utiliser ce projet comme base

### Ajouter une fonctionnalité

**1. Migration SQL** — `migrations/0003_ma_feature.sql` :
```sql
CREATE TABLE scores (
    id         UUID        PRIMARY KEY,
    user_id    UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    points     INTEGER     NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

**2. Handler Rust** — dans `src/handlers.rs` :
```rust
pub async fn mes_scores(State(s): State<AppState>, headers: HeaderMap) -> Response {
    let auth = match auth_session(&s.db, &headers).await { Ok(u) => u, Err(e) => return e };
    // auth.id   = UUID de l'utilisateur connecté
    // auth.role = "user" ou "admin"
    let rows = sqlx::query_as::<_, MonScore>(
        "SELECT * FROM scores WHERE user_id = $1 ORDER BY created_at DESC"
    )
    .bind(auth.id)
    .fetch_all(&s.db)
    .await;
    match rows {
        Ok(data) => Json(data).into_response(),
        Err(_)   => error_response(StatusCode::INTERNAL_SERVER_ERROR, "Erreur DB"),
    }
}
```

**3. Route** — dans `src/main.rs` :
```rust
.route("/scores", get(handlers::mes_scores))
```

**4. Frontend** — dans `static/js/app.js` :
```js
const scores = await api("scores");
```

### Checklist pour un nouveau projet

- [ ] Copier ce répertoire et renommer dans `Cargo.toml`
- [ ] Créer la base PostgreSQL et renseigner `DATABASE_URL` dans `.env`
- [ ] Lancer `cargo run` (les migrations s'appliquent automatiquement)
- [ ] S'inscrire → 1er compte = admin, appareil auto-approuvé
- [ ] Ajouter ses propres tables dans une migration `0003_*.sql`
- [ ] Écrire ses handlers dans `handlers.rs` en réutilisant `auth_session()`
- [ ] Brancher les routes dans `main.rs`
- [ ] Mettre à jour le frontend dans `static/`

### Ce qu'il ne faut pas modifier

- `src/auth.rs` — sécurité éprouvée, modifier avec précaution
- `migrations/0001_init.sql` et `0002_security.sql` — créer de nouvelles migrations plutôt

---

## Tests réalisés (18 catégories)

| # | Test | Résultat |
|---|---|---|
| 1 | Register (1er user = admin) | ✅ |
| 2 | Login admin + cookie session | ✅ |
| 3 | GET /me | ✅ |
| 4 | Register user normal | ✅ |
| 5 | Login user (appareil en attente) → 403 | ✅ |
| 6 | Admin liste les appareils | ✅ |
| 7 | Admin approuve l'appareil | ✅ |
| 8 | Login user après approbation | ✅ |
| 9 | Admin modifie rôle/active | ✅ |
| 10 | Liste des sessions | ✅ |
| 11 | Révocation d'une session | ✅ |
| 12 | Logout + logout-all | ✅ |
| 13 | Journal d'audit | ✅ |
| 14 | Contrôles d'accès (403 pour non-admin) | ✅ |
| 15 | Anti-verrouillage admin | ✅ |
| 16 | Protection IDOR sessions | ✅ |
| 17 | Prévention énumération emails | ✅ |
| 18 | Appareil révoqué bloque la connexion | ✅ |
