-- ── Migration initiale : schéma de base ───────────────────────────────────────
--
-- SQLx applique les migrations dans l'ordre alphabétique et les trace dans la
-- table _sqlx_migrations. Une migration déjà appliquée n'est jamais ré-exécutée.
--
-- POUR MODIFIER LE SCHÉMA :
--   Ne pas modifier ce fichier → créer une nouvelle migration (0003_ma_feature.sql)
--   qui utilise ALTER TABLE / CREATE TABLE.

-- ── Table des utilisateurs ────────────────────────────────────────────────────
CREATE TABLE users (
    id            UUID        PRIMARY KEY,
    email         TEXT        NOT NULL UNIQUE,
    password_hash TEXT        NOT NULL,           -- Hash Argon2id (jamais le mot de passe brut)
    role          TEXT        NOT NULL DEFAULT 'user'
                              CHECK (role IN ('user', 'admin')),
    active        BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Table des appareils ───────────────────────────────────────────────────────
-- Un appareil = un navigateur/machine. Identifié par un token aléatoire
-- stocké dans le cookie app_device (1 an).
CREATE TABLE devices (
    id           UUID        PRIMARY KEY,
    user_id      UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    label        TEXT        NOT NULL DEFAULT 'Navigateur', -- Nom lisible (ex: "Firefox sur Mac")
    token_hash   TEXT        NOT NULL UNIQUE,  -- SHA-256(device_token) — jamais le token brut
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked      BOOLEAN     NOT NULL DEFAULT FALSE
);
CREATE INDEX devices_user_id_idx ON devices(user_id);

-- ── Table des sessions ────────────────────────────────────────────────────────
-- Une session = une connexion active. Expire après 7 jours.
-- Liée à un appareil (utile pour afficher "connecté depuis Chrome sur Windows").
CREATE TABLE sessions (
    id         UUID        PRIMARY KEY,
    user_id    UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id  UUID                 REFERENCES devices(id) ON DELETE SET NULL,
    token_hash TEXT        NOT NULL UNIQUE,  -- SHA-256(session_token)
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked    BOOLEAN     NOT NULL DEFAULT FALSE
);
CREATE INDEX sessions_user_id_idx ON sessions(user_id);
