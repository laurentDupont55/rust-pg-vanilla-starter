// ── Utilitaires cryptographiques et helpers d'authentification ────────────────
//
// Ce module centralise :
//   • La génération et le hachage des tokens de session/appareil
//   • La construction et lecture des cookies HTTP
//   • L'extraction de l'utilisateur authentifié depuis une requête
//   • L'écriture dans le journal d'audit
//
// PRINCIPES DE SÉCURITÉ APPLIQUÉS :
//   - Les tokens sont générés aléatoirement (CSPRNG) et jamais stockés bruts
//   - En DB on ne stocke que SHA-256(token) → une fuite de DB ne compromet pas les sessions
//   - Les cookies sont HttpOnly (inaccessibles au JS) + SameSite=Lax (protection CSRF)

use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use rand::{rngs::OsRng, RngCore};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

// ── Génération de tokens ──────────────────────────────────────────────────────

/// Génère un token aléatoire de 256 bits (32 octets) encodé en hexadécimal (64 chars).
/// Utilise OsRng (CSPRNG fourni par le système d'exploitation) — imprévisible même
/// si l'état interne de l'application est connu.
pub fn random_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Hash un token avec SHA-256. C'est ce hash qui est stocké en base de données.
/// Ainsi, si la DB est compromise, l'attaquant ne peut pas réutiliser les tokens.
/// SHA-256 est suffisant ici car les tokens sont déjà de haute entropie (256 bits).
pub fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

// ── Gestion des cookies ───────────────────────────────────────────────────────

/// Construit la valeur d'un header Set-Cookie sécurisé.
/// - HttpOnly : le cookie est invisible depuis JavaScript (protection XSS)
/// - SameSite=Lax : le cookie n'est envoyé que sur les requêtes "first-party"
///   ou GET cross-site (protection contre CSRF)
/// - max_age en secondes : durée de vie du cookie dans le navigateur
///
/// En production, ajouter "; Secure" pour forcer HTTPS.
pub fn cookie(name: &str, value: &str, max_age: i64) -> String {
    format!("{name}={value}; HttpOnly; SameSite=Lax; Path=/; Max-Age={max_age}")
}

/// Crée un cookie "effaceur" : Max-Age=0 force le navigateur à supprimer le cookie.
pub fn clear_cookie(name: &str) -> String {
    format!("{name}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0")
}

/// Extrait la valeur d'un cookie nommé depuis le header "Cookie" d'une requête.
/// Le header Cookie contient tous les cookies séparés par ";".
pub fn get_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|part| {
            let (k, v) = part.trim().split_once('=')?;
            (k == name).then(|| v.to_string())
        })
}

// ── Extraction de métadonnées réseau ─────────────────────────────────────────

/// Tente d'extraire l'IP du client depuis le header X-Forwarded-For.
/// Ce header est positionné par les reverse proxies (nginx, Cloudflare…).
/// En développement direct, ce header est absent → retourne None.
pub fn get_ip(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        // X-Forwarded-For peut contenir plusieurs IPs séparées par virgule
        // (client, proxy1, proxy2…). On prend la première (l'originale).
        .map(|s| s.split(',').next().unwrap_or(s).trim().to_string())
}

/// Extrait le User-Agent (navigateur/OS) pour aider à identifier l'appareil.
pub fn get_ua(headers: &HeaderMap) -> Option<String> {
    headers
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
}

// ── Réponses d'erreur standardisées ──────────────────────────────────────────

/// Structure JSON retournée par toutes les réponses simples (succès ou erreur).
#[derive(Serialize)]
pub struct ApiMessage {
    pub message: String,
}

/// Crée une réponse HTTP d'erreur avec le code et le message fournis.
/// Toutes les erreurs de l'API ont le même format JSON : {"message": "..."}.
pub fn error_response(status: StatusCode, msg: &str) -> Response {
    (status, Json(ApiMessage { message: msg.into() })).into_response()
}

// ── Extraction de l'utilisateur authentifié ───────────────────────────────────

/// Représente un utilisateur authentifié extrait d'une session valide.
/// Passé aux handlers qui nécessitent une authentification.
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub id: Uuid,
    pub email: String,
    pub role: String,       // "user" ou "admin"
    pub session_id: Uuid,   // ID de la session courante (utile pour is_current)
}

/// Vérifie le cookie app_session et retourne l'utilisateur authentifié.
///
/// La requête SQL joint sessions + users pour vérifier en un seul aller-retour :
///   • Le token de session correspond à un enregistrement en DB
///   • La session n'est ni révoquée ni expirée
///   • Le compte utilisateur est actif
///
/// Retourne Err(Response 401) si l'une de ces conditions n'est pas satisfaite.
pub async fn auth_session(db: &PgPool, headers: &HeaderMap) -> Result<AuthUser, Response> {
    let token = get_cookie(headers, "app_session")
        .ok_or_else(|| error_response(StatusCode::UNAUTHORIZED, "Non connecté."))?;

    // On hash le token reçu pour comparer avec ce qui est en DB (jamais le brut)
    let hash = token_hash(&token);

    let row = sqlx::query_as::<_, (Uuid, Uuid, String, String)>(
        "SELECT se.id, u.id, u.email, u.role
         FROM sessions se
         JOIN users u ON u.id = se.user_id
         WHERE se.token_hash = $1
           AND se.revoked = false
           AND se.expires_at > NOW()
           AND u.active = true",
    )
    .bind(hash)
    .fetch_optional(db)
    .await;

    match row {
        Ok(Some((session_id, user_id, email, role))) => Ok(AuthUser {
            id: user_id,
            email,
            role,
            session_id,
        }),
        Ok(None) => Err(error_response(
            StatusCode::UNAUTHORIZED,
            "Session expirée ou invalide.",
        )),
        Err(_) => Err(error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Erreur base de données.",
        )),
    }
}

/// Comme auth_session, mais vérifie en plus que l'utilisateur est administrateur.
/// Retourne Err(Response 403) si l'utilisateur n'a pas le rôle "admin".
///
/// Le rôle est relu depuis la DB à chaque requête → un changement de rôle
/// est immédiatement effectif sans avoir à invalider les sessions.
pub async fn auth_admin(db: &PgPool, headers: &HeaderMap) -> Result<AuthUser, Response> {
    let user = auth_session(db, headers).await?;
    if user.role != "admin" {
        return Err(error_response(
            StatusCode::FORBIDDEN,
            "Réservé aux administrateurs.",
        ));
    }
    Ok(user)
}

// ── Journal d'audit ───────────────────────────────────────────────────────────

/// Enregistre une action dans la table audit_logs.
/// Cette fonction est "fire and forget" : on ignore silencieusement les erreurs
/// d'écriture du journal pour ne pas bloquer le flux principal.
///
/// Paramètres :
///   - user_id    : qui a effectué l'action (None si non authentifié)
///   - action     : verbe de l'action ("login", "device_approved"…)
///   - target_id  : UUID de l'entité concernée (appareil, session, user…)
///   - target_type: type de l'entité ("device", "session", "user")
///   - ip         : adresse IP du client
///   - ua         : User-Agent du navigateur
///   - details    : données JSON supplémentaires (ex: {"new_role": "admin"})
pub async fn audit_log(
    db: &PgPool,
    user_id: Option<Uuid>,
    action: &str,
    target_id: Option<Uuid>,
    target_type: Option<&str>,
    ip: Option<&str>,
    ua: Option<&str>,
    details: Option<serde_json::Value>,
) {
    let _ = sqlx::query(
        "INSERT INTO audit_logs
            (id, user_id, action, target_id, target_type, ip_address, user_agent, details)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(Uuid::new_v4())
    .bind(user_id)
    .bind(action)
    .bind(target_id)
    .bind(target_type)
    .bind(ip)
    .bind(ua)
    .bind(details)
    .execute(db)
    .await;
}
