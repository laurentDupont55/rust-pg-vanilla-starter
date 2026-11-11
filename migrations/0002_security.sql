-- ── Migration de sécurité : approbation des appareils + journal d'audit ────────
--
-- Cette migration ajoute deux fonctionnalités :
--   1. Approbation admin des appareils : un appareil inconnu ne peut se connecter
--      qu'après validation par un administrateur.
--   2. Journal d'audit : traçabilité complète des actions (connexions, modifications…).

-- ── Ajout des colonnes d'approbation sur devices ──────────────────────────────
ALTER TABLE devices
    -- Statut d'approbation : false = en attente, true = approuvé
    ADD COLUMN IF NOT EXISTS approved    BOOLEAN     NOT NULL DEFAULT FALSE,
    -- Date et auteur de l'approbation (traçabilité)
    ADD COLUMN IF NOT EXISTS approved_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS approved_by UUID        REFERENCES users(id) ON DELETE SET NULL,
    -- Nom personnalisé donné à l'appareil par l'utilisateur (facultatif)
    ADD COLUMN IF NOT EXISTS name        TEXT,
    -- Métadonnées réseau pour aider à identifier l'appareil dans l'interface
    ADD COLUMN IF NOT EXISTS user_agent  TEXT,
    ADD COLUMN IF NOT EXISTS ip_address  TEXT;

-- Rétrocompatibilité : les appareils existants (avant cette migration) sont
-- automatiquement approuvés pour ne pas bloquer les utilisateurs déjà connectés.
UPDATE devices SET approved = TRUE WHERE approved = FALSE;

-- ── Table des journaux d'audit ────────────────────────────────────────────────
--
-- Enregistre toutes les actions significatives.
-- Actions possibles : login, login_failed, logout, logout_all,
--   device_registered, device_approved, device_revoked,
--   session_revoked, user_activated, user_deactivated, role_changed
--
-- POUR AJOUTER DES ACTIONS :
--   Appeler audit_log() dans le handler correspondant (src/auth.rs).
--   Pas besoin de modifier cette table (action est un TEXT libre).
CREATE TABLE IF NOT EXISTS audit_logs (
    id          UUID        PRIMARY KEY,
    user_id     UUID        REFERENCES users(id) ON DELETE SET NULL, -- NULL si compte supprimé
    action      TEXT        NOT NULL,
    target_id   UUID,                   -- UUID de l'entité concernée (optionnel)
    target_type TEXT,                   -- "user", "device" ou "session"
    ip_address  TEXT,                   -- IP du client au moment de l'action
    user_agent  TEXT,                   -- Navigateur/OS
    details     JSONB,                  -- Données supplémentaires (ex: ancien/nouveau rôle)
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index pour accélérer les requêtes fréquentes dans l'interface d'administration
CREATE INDEX IF NOT EXISTS audit_logs_user_id_idx    ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS audit_logs_created_at_idx ON audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS audit_logs_action_idx     ON audit_logs(action);
