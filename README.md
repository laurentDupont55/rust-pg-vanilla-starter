# rust-pg-vanilla-starter

Starter d'authentification sécurisé prêt à l'emploi, conçu pour servir de base à n'importe quelle application web.

**Stack :** Rust + Axum 0.8 · PostgreSQL · SQLx · Argon2id · Vanilla JS

---

## Fonctionnalités

- **Inscription / Connexion** — hash Argon2id, tokens 256 bits, cookies HttpOnly + SameSite
- **Gestion des appareils** — chaque navigateur reçoit un cookie appareil persistant ; les nouveaux appareils doivent être approuvés par un admin avant de pouvoir se connecter
- **Gestion des sessions** — expiration 7 jours, liste des sessions actives, révocation unitaire ou globale
- **Rôles** — `user` / `admin` ; premier inscrit automatiquement admin
- **Interface d'administration** — approbation des appareils, gestion des utilisateurs, journal d'audit complet
- **Journal d'audit** — toutes les actions significatives tracées en base (connexions, approbations, révocations…)

---

## Prérequis

- [Rust stable](https://rustup.rs/)
- PostgreSQL 14 ou supérieur

---

## Démarrage rapide

```bash
# 1. Cloner le projet
git clone https://github.com/laurentDupont55/rust-pg-vanilla-starter.git
cd rust-pg-vanilla-starter

# 2. Créer la base PostgreSQL
createdb app_db

# 3. Configurer l'environnement
cp .env.example .env
# Éditer DATABASE_URL dans .env

# 4. Lancer l'application (les migrations s'appliquent automatiquement)
cargo run
```

Ouvrir http://127.0.0.1:3000

**Premier compte :** le premier utilisateur inscrit obtient automatiquement le rôle `admin` et son appareil est auto-approuvé.

---

## Structure du projet

```
src/
├── main.rs      → démarrage, router HTTP (ajouter les routes ici)
├── state.rs     → AppState partagé entre les handlers
├── auth.rs      → crypto, cookies, vérification de session, audit
└── handlers.rs  → toute la logique métier (ajouter les handlers ici)

migrations/
├── 0001_init.sql      → tables users, devices, sessions
└── 0002_security.sql  → approbation des appareils + journal d'audit

static/
├── index.html   → SPA — login, dashboard, administration
├── css/style.css
└── js/app.js    → appels API, construction du DOM
```

---

## API

### Authentification

| Méthode | Route | Description |
|---|---|---|
| `POST` | `/api/register` | Créer un compte |
| `POST` | `/api/login` | Ouvrir une session |
| `GET` | `/api/me` | Profil de l'utilisateur connecté |
| `POST` | `/api/logout` | Fermer la session courante |
| `POST` | `/api/logout-all` | Fermer toutes ses sessions |

### Sessions

| Méthode | Route | Description |
|---|---|---|
| `GET` | `/api/sessions` | Lister ses sessions actives |
| `POST` | `/api/sessions/{id}/revoke` | Révoquer une session |

### Administration *(rôle admin requis)*

| Méthode | Route | Description |
|---|---|---|
| `GET` | `/api/admin/users` | Lister tous les utilisateurs |
| `PATCH` | `/api/admin/users/{id}` | Modifier rôle / activer / désactiver |
| `GET` | `/api/admin/devices` | Lister tous les appareils |
| `POST` | `/api/admin/devices/{id}/approve` | Approuver un appareil |
| `POST` | `/api/admin/devices/{id}/revoke` | Révoquer un appareil |
| `GET` | `/api/admin/logs` | Journal d'audit paginé |

---

## Utiliser ce projet comme base

### 1. Ajouter une table

Créer `migrations/0003_ma_feature.sql` :

```sql
CREATE TABLE scores (
    id         UUID        PRIMARY KEY,
    user_id    UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    points     INTEGER     NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

### 2. Ajouter un handler

Dans `src/handlers.rs` :

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

### 3. Brancher la route

Dans `src/main.rs` :

```rust
.route("/scores", get(handlers::mes_scores))
```

### 4. Appeler depuis le frontend

Dans `static/js/app.js` :

```js
const scores = await api("scores");
```

---

## Sécurité

- Tokens de 256 bits (OsRng) — seul le SHA-256 est stocké en base
- Mots de passe hashés avec Argon2id (sel aléatoire par utilisateur)
- Cookies `HttpOnly` + `SameSite=Lax` (pas d'accès JS, protection CSRF)
- Protection IDOR : les sessions ne peuvent être révoquées que par leur propriétaire
- Prévention d'énumération des emails : même message d'erreur pour email inconnu / mauvais mot de passe
- Rôle lu en base à chaque requête (un changement de rôle est immédiat)
- Protection anti-verrouillage : un admin ne peut pas désactiver son propre compte

### Avant une mise en production

- [ ] Activer HTTPS et passer les cookies en `Secure`
- [ ] Ajouter une limitation de débit sur `/api/login` et `/api/register` (anti-bruteforce)
- [ ] Fermer l'inscription publique si l'application est interne
- [ ] Configurer `BIND_ADDR` et les variables d'environnement via des secrets système (pas `.env`)

---

## Variables d'environnement

| Variable | Exemple | Description |
|---|---|---|
| `DATABASE_URL` | `postgres://user:pass@localhost/app_db` | Connexion PostgreSQL |
| `BIND_ADDR` | `127.0.0.1:3000` | Adresse d'écoute (défaut : `127.0.0.1:3000`) |
