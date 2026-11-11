// ── Handlers HTTP ─────────────────────────────────────────────────────────────
//
// Ce fichier contient tous les handlers de l'API.
// Un handler est une fonction async appelée par Axum quand une route correspond.
//
// CONVENTIONS :
//   • Chaque handler retourne `Response` (type opaque qui englobe status + headers + body)
//   • Les handlers publics (endpoint admin) appellent auth_admin() en premier
//   • Les handlers authentifiés normaux appellent auth_session() en premier
//   • SQLx utilise des requêtes paramétrées ($1, $2…) → protection SQL injection
//
// POUR AJOUTER UN ENDPOINT :
//   1. Définir les structs d'entrée/sortie (Deserialize/Serialize)
//   2. Écrire la fonction async pub
//   3. L'enregistrer dans main.rs

use crate::auth::{
    audit_log, auth_admin, auth_session, clear_cookie, cookie, error_response, get_cookie,
    get_ip, get_ua, random_token, token_hash, ApiMessage,
};
use crate::state::AppState;
use argon2::{
    password_hash::{PasswordHash, SaltString},
    Argon2, PasswordHasher, PasswordVerifier,
};
use axum::{
    extract::{Json, Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

// ══════════════════════════════════════════════════════════════════════════════
// STRUCTS D'ENTRÉE (corps des requêtes JSON)
// ══════════════════════════════════════════════════════════════════════════════

/// Corps de la requête POST /api/register
#[derive(Deserialize)]
pub struct RegisterInput {
    email: String,
    password: String,
}

/// Corps de la requête POST /api/login
#[derive(Deserialize)]
pub struct LoginInput {
    email: String,
    password: String,
}

/// Corps de la requête PATCH /api/admin/users/{id}
/// Les deux champs sont optionnels : on peut modifier l'un, l'autre ou les deux.
#[derive(Deserialize)]
pub struct UpdateUserInput {
    active: Option<bool>,   // true = activer, false = désactiver
    role: Option<String>,   // "user" ou "admin"
}

/// Paramètres de pagination pour GET /api/admin/logs?page=1&limit=50
#[derive(Deserialize, Default)]
pub struct PaginationParams {
    page: Option<i64>,
    limit: Option<i64>,
}

// ══════════════════════════════════════════════════════════════════════════════
// STRUCTS DE SORTIE (lignes DB → JSON)
// sqlx::FromRow permet à SQLx de remplir ces structs automatiquement depuis
// les résultats de requêtes SQL (sans écrire de mapping manuel).
// ══════════════════════════════════════════════════════════════════════════════

/// Une ligne de la table users, retournée dans les listes admin.
#[derive(sqlx::FromRow, Serialize)]
struct UserRow {
    id: Uuid,
    email: String,
    role: String,
    active: bool,
    created_at: chrono::DateTime<chrono::Utc>,
}

/// Un appareil avec l'email de son propriétaire (JOIN devices + users).
#[derive(sqlx::FromRow, Serialize)]
struct DeviceRow {
    id: Uuid,
    user_id: Uuid,
    user_email: String,       // email du propriétaire (JOIN)
    device_label: String,     // COALESCE(name, label) : nom personnalisé ou "Navigateur"
    created_at: chrono::DateTime<chrono::Utc>,
    last_seen_at: chrono::DateTime<chrono::Utc>,
    revoked: bool,
    approved: bool,
    approved_at: Option<chrono::DateTime<chrono::Utc>>,
    user_agent: Option<String>,
    ip_address: Option<String>,
}

/// Une session avec les infos de l'appareil associé.
/// Pas de Serialize : on construit le JSON manuellement pour ajouter is_current.
#[derive(sqlx::FromRow)]
struct SessionRow {
    id: Uuid,
    device_label: String,
    device_ua: Option<String>,   // User-Agent de l'appareil
    device_ip: Option<String>,   // IP lors de l'enregistrement
    created_at: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
}

/// Une entrée du journal d'audit.
#[derive(sqlx::FromRow, Serialize)]
struct LogRow {
    id: Uuid,
    user_email: Option<String>,  // NULL si le compte a été supprimé
    action: String,
    target_id: Option<Uuid>,
    target_type: Option<String>,
    ip_address: Option<String>,
    user_agent: Option<String>,
    details: Option<serde_json::Value>, // JSONB : données supplémentaires
    created_at: chrono::DateTime<chrono::Utc>,
}

// ══════════════════════════════════════════════════════════════════════════════
// HELPER INTERNE — Enregistrement d'un nouvel appareil
// ══════════════════════════════════════════════════════════════════════════════

/// Crée un enregistrement device en DB pour un utilisateur.
///
/// Retourne Ok((device_id, device_token)) si l'appareil est immédiatement approuvé
/// (cas des administrateurs), ou Err(Response 403 avec cookie device) si
/// l'appareil est en attente d'approbation par un admin.
///
/// Logique d'approbation automatique :
///   - Les administrateurs : leurs appareils sont auto-approuvés
///   - Les utilisateurs normaux : nécessitent une approbation manuelle
///
/// En retournant Err(response) pour le cas "pending", on peut utiliser l'opérateur ?
/// ou un pattern matching dans le handler appelant pour retourner tôt.
async fn create_device(
    db: &PgPool,
    user_id: Uuid,
    role: &str,
    ua: Option<&str>,
    ip: Option<&str>,
) -> Result<(Uuid, String), Response> {
    let device_token = random_token();
    let device_hash = token_hash(&device_token);
    let device_id = Uuid::new_v4();
    // Seuls les admins ont un appareil auto-approuvé
    let auto_approve = role == "admin";

    if sqlx::query(
        "INSERT INTO devices (id, user_id, label, token_hash, approved, user_agent, ip_address)
         VALUES ($1, $2, 'Navigateur', $3, $4, $5, $6)",
    )
    .bind(device_id)
    .bind(user_id)
    .bind(&device_hash)
    .bind(auto_approve)
    .bind(ua)
    .bind(ip)
    .execute(db)
    .await
    .is_err()
    {
        return Err(error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Impossible d'enregistrer l'appareil.",
        ));
    }

    audit_log(db, Some(user_id), "device_registered", Some(device_id), Some("device"), ip, ua, None).await;

    if !auto_approve {
        // On définit quand même le cookie device pour que, lors de la prochaine
        // tentative de connexion (après approbation), le navigateur envoie ce cookie
        // et qu'on puisse retrouver cet appareil en DB.
        let mut resp = error_response(
            StatusCode::FORBIDDEN,
            "Nouvel appareil détecté et enregistré. En attente d'approbation par un administrateur.",
        );
        resp.headers_mut().append(
            header::SET_COOKIE,
            cookie("app_device", &device_token, 365 * 86400).parse().unwrap(),
        );
        return Err(resp);
    }

    Ok((device_id, device_token))
}

// ══════════════════════════════════════════════════════════════════════════════
// ENDPOINTS PUBLICS (pas d'authentification requise)
// ══════════════════════════════════════════════════════════════════════════════

/// GET /api/health → {"message": "OK"}
/// Utilisé pour vérifier que l'application répond (healthcheck Docker, load balancer…).
pub async fn health() -> Json<ApiMessage> {
    Json(ApiMessage { message: "OK".into() })
}

/// POST /api/register → 201 {"id", "email", "role"}
///
/// Crée un nouveau compte utilisateur.
/// Le premier utilisateur inscrit reçoit automatiquement le rôle "admin".
/// Tous les suivants reçoivent le rôle "user" par défaut.
///
/// POUR AJOUTER DES CHAMPS : étendre RegisterInput, ajouter les colonnes en DB,
/// les passer dans la requête INSERT.
pub async fn register(
    State(s): State<AppState>,
    Json(input): Json<RegisterInput>,
) -> Response {
    let email = input.email.trim().to_lowercase(); // Normalisation : minuscules + sans espaces

    // Validation minimale avant de solliciter la DB
    if !email.contains('@') || input.password.len() < 12 {
        return error_response(
            StatusCode::BAD_REQUEST,
            "Email invalide ou mot de passe trop court (12 caractères minimum).",
        );
    }

    // Hachage du mot de passe avec Argon2id.
    // SaltString::generate crée un sel aléatoire unique à chaque utilisateur
    // → deux utilisateurs avec le même mdp ont des hashs différents.
    let salt = SaltString::generate(&mut OsRng);
    let hash = match Argon2::default().hash_password(input.password.as_bytes(), &salt) {
        Ok(h) => h.to_string(),
        Err(_) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Erreur de hash."),
    };

    // Déterminer le rôle : premier utilisateur → admin
    let count: i64 = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users")
        .fetch_one(&s.db)
        .await
        .unwrap_or(1); // En cas d'erreur DB, on ne crée pas d'admin par défaut
    let role = if count == 0 { "admin" } else { "user" };

    let id = Uuid::new_v4();
    match sqlx::query(
        "INSERT INTO users (id, email, password_hash, role) VALUES ($1, $2, $3, $4)",
    )
    .bind(id)
    .bind(&email)
    .bind(&hash)
    .bind(role)
    .execute(&s.db)
    .await
    {
        Ok(_) => (
            StatusCode::CREATED,
            Json(serde_json::json!({ "id": id, "email": email, "role": role })),
        ).into_response(),
        // Code PostgreSQL 23505 = violation de contrainte UNIQUE (email déjà pris)
        Err(sqlx::Error::Database(e)) if e.code().as_deref() == Some("23505") => {
            error_response(StatusCode::CONFLICT, "Cet email est déjà utilisé.")
        }
        Err(_) => error_response(StatusCode::INTERNAL_SERVER_ERROR, "Erreur base de données."),
    }
}

/// POST /api/login → 200 {"id", "email", "role"} + cookies app_session + app_device
///
/// Flux complet de connexion avec gestion des appareils :
///
///   1. Vérifier email + mot de passe (Argon2id)
///   2. Chercher l'appareil via le cookie app_device (s'il existe)
///      a. Appareil trouvé + approuvé → continuer
///      b. Appareil trouvé + non approuvé → 403 "en attente"
///      c. Appareil trouvé + révoqué → 403 "révoqué"
///      d. Cookie absent ou orphelin → enregistrer nouvel appareil
///         - Si admin : auto-approuvé → continuer
///         - Sinon : 403 "en attente d'approbation" + cookie device
///   3. Créer une session (expire dans 7 jours)
///   4. Retourner les infos utilisateur + cookies session et appareil
pub async fn login(
    State(s): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<LoginInput>,
) -> Response {
    let email = input.email.trim().to_lowercase();
    let ip = get_ip(&headers);
    let ua = get_ua(&headers);

    // ── Étape 1 : Vérifier les identifiants ──────────────────────────────────

    let row = sqlx::query_as::<_, (Uuid, String, String, bool, String)>(
        "SELECT id, email, password_hash, active, role FROM users WHERE email = $1",
    )
    .bind(&email)
    .fetch_optional(&s.db)
    .await;

    let (user_id, user_email, hash, active, role) = match row {
        Ok(Some(r)) => r,
        // On retourne le même message que pour un mauvais mot de passe
        // pour ne pas révéler si l'email existe (user enumeration)
        Ok(None) => return error_response(StatusCode::UNAUTHORIZED, "Identifiants incorrects."),
        Err(_) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Erreur base de données."),
    };

    if !active {
        return error_response(StatusCode::FORBIDDEN, "Compte désactivé.");
    }

    // Vérification Argon2id : compare le mdp fourni avec le hash stocké
    let parsed = match PasswordHash::new(&hash) {
        Ok(h) => h,
        Err(_) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Erreur interne."),
    };
    if Argon2::default().verify_password(input.password.as_bytes(), &parsed).is_err() {
        // On journalise la tentative échouée (utile pour détecter les attaques)
        audit_log(&s.db, Some(user_id), "login_failed", None, None, ip.as_deref(), ua.as_deref(), None).await;
        // Même message que "email inexistant" → opaque à l'attaquant
        return error_response(StatusCode::UNAUTHORIZED, "Identifiants incorrects.");
    }

    // ── Étape 2 : Identifier l'appareil ──────────────────────────────────────

    // On cherche si un cookie app_device est présent dans la requête
    let device_cookie = get_cookie(&headers, "app_device");
    let existing_device: Option<(Uuid, Uuid, bool, bool)> = if let Some(ref token) = device_cookie {
        // On hash le token reçu pour le comparer au hash stocké en DB
        let dh = token_hash(token);
        match sqlx::query_as::<_, (Uuid, Uuid, bool, bool)>(
            "SELECT id, user_id, approved, revoked FROM devices WHERE token_hash = $1",
        )
        .bind(&dh)
        .fetch_optional(&s.db)
        .await
        {
            Ok(v) => v,
            Err(_) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Erreur base de données."),
        }
    } else {
        None
    };

    // ── Étape 3 : Résoudre l'appareil (existant ou nouveau) ──────────────────

    // device_id    : ID de l'appareil à associer à la session
    // new_device_token : Some(token) si on vient de créer un appareil
    //                    (pour définir le cookie dans la réponse)
    let (device_id, new_device_token) = match existing_device {
        Some((dev_id, dev_user_id, approved, revoked)) => {
            // Sécurité : vérifier que cet appareil appartient bien à CET utilisateur
            // (empêche qu'un cookie volé serve pour un autre compte)
            if dev_user_id != user_id {
                return error_response(StatusCode::UNAUTHORIZED, "Appareil invalide.");
            }
            if revoked {
                return error_response(StatusCode::FORBIDDEN, "Cet appareil a été révoqué.");
            }
            if !approved {
                return error_response(
                    StatusCode::FORBIDDEN,
                    "Cet appareil est en attente d'approbation par un administrateur.",
                );
            }
            // Mettre à jour la date de dernière vue de l'appareil
            let _ = sqlx::query("UPDATE devices SET last_seen_at = NOW() WHERE id = $1")
                .bind(dev_id).execute(&s.db).await;
            (dev_id, None) // Pas de nouveau cookie device à définir
        }
        None => {
            // Pas de cookie ou cookie orphelin → enregistrer un nouvel appareil
            match create_device(&s.db, user_id, &role, ua.as_deref(), ip.as_deref()).await {
                Ok((dev_id, token)) => (dev_id, Some(token)),
                // create_device retourne Err(resp) si l'appareil est en attente
                // → on retourne directement cette réponse 403 (avec le cookie device)
                Err(pending_resp) => return pending_resp,
            }
        }
    };

    // ── Étape 4 : Créer la session ────────────────────────────────────────────

    let session_token = random_token();
    let session_hash = token_hash(&session_token);
    let session_id = Uuid::new_v4();

    if sqlx::query(
        "INSERT INTO sessions (id, user_id, device_id, token_hash, expires_at)
         VALUES ($1, $2, $3, $4, NOW() + INTERVAL '7 days')",
    )
    .bind(session_id).bind(user_id).bind(device_id).bind(&session_hash)
    .execute(&s.db).await.is_err()
    {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Impossible de créer la session.");
    }

    audit_log(&s.db, Some(user_id), "login", Some(session_id), Some("session"), ip.as_deref(), ua.as_deref(), None).await;

    // ── Étape 5 : Construire la réponse avec les cookies ──────────────────────

    let mut response = (
        StatusCode::OK,
        Json(serde_json::json!({ "id": user_id, "email": user_email, "role": role })),
    ).into_response();

    // Cookie de session : 7 jours, HttpOnly (non lisible en JS)
    response.headers_mut().append(
        header::SET_COOKIE,
        cookie("app_session", &session_token, 7 * 86400).parse().unwrap(),
    );
    // Cookie d'appareil : 1 an, défini uniquement si un nouvel appareil a été créé
    if let Some(ref new_token) = new_device_token {
        response.headers_mut().append(
            header::SET_COOKIE,
            cookie("app_device", new_token, 365 * 86400).parse().unwrap(),
        );
    }
    response
}

/// GET /api/me → 200 {"id", "email", "role"}
///
/// Retourne le profil de l'utilisateur connecté.
/// Utilisé par le frontend au chargement de la page pour restaurer la session.
/// Si le cookie est absent ou la session expirée → 401.
pub async fn me(State(s): State<AppState>, headers: HeaderMap) -> Response {
    match auth_session(&s.db, &headers).await {
        Ok(u) => Json(serde_json::json!({ "id": u.id, "email": u.email, "role": u.role }))
            .into_response(),
        Err(e) => e,
    }
}

/// POST /api/logout → 200 + suppression du cookie app_session
///
/// Marque la session courante comme révoquée en DB et efface le cookie.
/// Le cookie app_device reste en place pour les reconnexions futures.
pub async fn logout(State(s): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(token) = get_cookie(&headers, "app_session") {
        let hash = token_hash(&token);
        // On journalise avant de révoquer (pour avoir l'ID de session dans les logs)
        if let Ok(user) = auth_session(&s.db, &headers).await {
            audit_log(&s.db, Some(user.id), "logout", Some(user.session_id), Some("session"), None, None, None).await;
        }
        let _ = sqlx::query("UPDATE sessions SET revoked = true WHERE token_hash = $1")
            .bind(hash).execute(&s.db).await;
    }
    let mut resp = Json(ApiMessage { message: "Déconnecté.".into() }).into_response();
    // Max-Age=0 demande au navigateur de supprimer immédiatement le cookie
    resp.headers_mut().append(header::SET_COOKIE, clear_cookie("app_session").parse().unwrap());
    resp
}

/// POST /api/logout-all → 200 + suppression cookie
///
/// Révoque TOUTES les sessions de l'utilisateur (tous ses appareils).
/// Utile en cas de compromission de compte suspectée.
pub async fn logout_all(State(s): State<AppState>, headers: HeaderMap) -> Response {
    let auth = match auth_session(&s.db, &headers).await {
        Ok(u) => u,
        Err(e) => return e,
    };
    let _ = sqlx::query("UPDATE sessions SET revoked = true WHERE user_id = $1")
        .bind(auth.id).execute(&s.db).await;
    audit_log(&s.db, Some(auth.id), "logout_all", None, None, None, None, None).await;
    let mut resp = Json(ApiMessage { message: "Toutes les sessions ont été révoquées.".into() }).into_response();
    resp.headers_mut().append(header::SET_COOKIE, clear_cookie("app_session").parse().unwrap());
    resp
}

// ══════════════════════════════════════════════════════════════════════════════
// GESTION DES SESSIONS
// ══════════════════════════════════════════════════════════════════════════════

/// GET /api/sessions → liste des sessions actives de l'utilisateur connecté
///
/// Chaque session inclut is_current=true pour la session en cours
/// (permet au frontend de la mettre en évidence et de proposer "déconnecter cet appareil").
pub async fn list_sessions(State(s): State<AppState>, headers: HeaderMap) -> Response {
    let auth = match auth_session(&s.db, &headers).await {
        Ok(u) => u,
        Err(e) => return e,
    };
    let rows = sqlx::query_as::<_, SessionRow>(
        "SELECT s.id,
                COALESCE(d.name, d.label, 'Appareil inconnu') AS device_label,
                d.user_agent AS device_ua,
                d.ip_address AS device_ip,
                s.created_at,
                s.expires_at
         FROM sessions s
         LEFT JOIN devices d ON d.id = s.device_id
         WHERE s.user_id = $1 AND s.revoked = false AND s.expires_at > NOW()
         ORDER BY s.created_at DESC",
    )
    .bind(auth.id)
    .fetch_all(&s.db)
    .await;

    match rows {
        Ok(sessions) => {
            let result: Vec<_> = sessions.into_iter().map(|s| {
                serde_json::json!({
                    "id": s.id,
                    "device_label": s.device_label,
                    "device_ua": s.device_ua,
                    "device_ip": s.device_ip,
                    "created_at": s.created_at,
                    "expires_at": s.expires_at,
                    // Comparaison avec la session courante pour marquer "cette session"
                    "is_current": s.id == auth.session_id,
                })
            }).collect();
            Json(result).into_response()
        }
        Err(_) => error_response(StatusCode::INTERNAL_SERVER_ERROR, "Erreur base de données."),
    }
}

/// POST /api/sessions/{id}/revoke → 200 ou 404
///
/// Révoque une session spécifique.
/// La clause `AND user_id = $2` empêche de révoquer la session d'un autre utilisateur
/// (protection contre les attaques IDOR).
pub async fn revoke_session(
    State(s): State<AppState>,
    headers: HeaderMap,
    Path(session_id): Path<Uuid>, // Axum extrait {id} de l'URL et le convertit en Uuid
) -> Response {
    let auth = match auth_session(&s.db, &headers).await {
        Ok(u) => u,
        Err(e) => return e,
    };
    let result = sqlx::query(
        // user_id = $2 garantit qu'on ne peut révoquer que ses propres sessions
        "UPDATE sessions SET revoked = true WHERE id = $1 AND user_id = $2",
    )
    .bind(session_id).bind(auth.id).execute(&s.db).await;

    match result {
        Ok(r) if r.rows_affected() == 0 => {
            // 404 et non 403 : on ne révèle pas si la session existe pour un autre user
            error_response(StatusCode::NOT_FOUND, "Session introuvable.")
        }
        Ok(_) => {
            audit_log(&s.db, Some(auth.id), "session_revoked", Some(session_id), Some("session"), None, None, None).await;
            let mut resp = Json(ApiMessage { message: "Session révoquée.".into() }).into_response();
            // Si l'utilisateur révoque sa propre session courante, effacer le cookie
            if session_id == auth.session_id {
                resp.headers_mut().append(header::SET_COOKIE, clear_cookie("app_session").parse().unwrap());
            }
            resp
        }
        Err(_) => error_response(StatusCode::INTERNAL_SERVER_ERROR, "Erreur base de données."),
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// ADMINISTRATION — UTILISATEURS
// ══════════════════════════════════════════════════════════════════════════════

/// GET /api/admin/users → liste de tous les utilisateurs
///
/// Route protégée : auth_admin() vérifie que le cookie correspond à un admin actif.
pub async fn admin_list_users(State(s): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(e) = auth_admin(&s.db, &headers).await {
        return e; // 401 si non connecté, 403 si pas admin
    }
    match sqlx::query_as::<_, UserRow>(
        "SELECT id, email, role, active, created_at FROM users ORDER BY created_at DESC",
    )
    .fetch_all(&s.db).await
    {
        Ok(users) => Json(users).into_response(),
        Err(_) => error_response(StatusCode::INTERNAL_SERVER_ERROR, "Erreur base de données."),
    }
}

/// PATCH /api/admin/users/{id} → {"message": "Utilisateur mis à jour."}
///
/// Modifie un ou deux champs d'un utilisateur.
/// Corps JSON (tout optionnel) : {"active": false} ou {"role": "admin"} ou les deux.
///
/// Protections :
///   - L'admin ne peut pas se désactiver lui-même (évite le lock-out)
///   - Les rôles invalides sont rejetés
///   - Désactiver un utilisateur révoque immédiatement toutes ses sessions
pub async fn admin_update_user(
    State(s): State<AppState>,
    headers: HeaderMap,
    Path(target_id): Path<Uuid>,
    Json(input): Json<UpdateUserInput>,
) -> Response {
    let admin = match auth_admin(&s.db, &headers).await {
        Ok(u) => u,
        Err(e) => return e,
    };
    if input.active.is_none() && input.role.is_none() {
        return error_response(StatusCode::BAD_REQUEST, "Aucune modification demandée.");
    }
    if let Some(ref role) = input.role {
        if role != "user" && role != "admin" {
            return error_response(StatusCode::BAD_REQUEST, "Rôle invalide (user ou admin).");
        }
    }
    // Protection anti-lock-out : impossible de se désactiver soi-même
    if input.active == Some(false) && target_id == admin.id {
        return error_response(StatusCode::BAD_REQUEST, "Vous ne pouvez pas désactiver votre propre compte.");
    }

    if let Some(active) = input.active {
        let _ = sqlx::query("UPDATE users SET active = $1 WHERE id = $2")
            .bind(active).bind(target_id).execute(&s.db).await;
        let action = if active { "user_activated" } else { "user_deactivated" };
        audit_log(&s.db, Some(admin.id), action, Some(target_id), Some("user"), None, None, None).await;
        // Désactivation immédiate : fermer toutes les sessions ouvertes
        if !active {
            let _ = sqlx::query("UPDATE sessions SET revoked = true WHERE user_id = $1")
                .bind(target_id).execute(&s.db).await;
        }
    }

    if let Some(ref role) = input.role {
        let _ = sqlx::query("UPDATE users SET role = $1 WHERE id = $2")
            .bind(role.as_str()).bind(target_id).execute(&s.db).await;
        audit_log(
            &s.db, Some(admin.id), "role_changed", Some(target_id), Some("user"),
            None, None,
            Some(serde_json::json!({ "new_role": role })), // Log du nouveau rôle
        ).await;
    }

    Json(ApiMessage { message: "Utilisateur mis à jour.".into() }).into_response()
}

// ══════════════════════════════════════════════════════════════════════════════
// ADMINISTRATION — APPAREILS
// ══════════════════════════════════════════════════════════════════════════════

/// GET /api/admin/devices → liste de tous les appareils
///
/// Triés par statut : en attente d'abord (priorité admin), puis approuvés, puis révoqués.
pub async fn admin_list_devices(State(s): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(e) = auth_admin(&s.db, &headers).await {
        return e;
    }
    match sqlx::query_as::<_, DeviceRow>(
        "SELECT d.id, d.user_id, u.email AS user_email,
                COALESCE(d.name, d.label) AS device_label,
                d.created_at, d.last_seen_at,
                d.revoked, d.approved, d.approved_at,
                d.user_agent, d.ip_address
         FROM devices d JOIN users u ON u.id = d.user_id
         ORDER BY
             -- Priorité 0 = en attente (s'affichent en premier pour l'admin)
             CASE WHEN d.revoked = false AND d.approved = false THEN 0
                  WHEN d.approved = true AND d.revoked = false THEN 1
                  ELSE 2 END,
             d.created_at DESC",
    )
    .fetch_all(&s.db).await
    {
        Ok(devices) => Json(devices).into_response(),
        Err(_) => error_response(StatusCode::INTERNAL_SERVER_ERROR, "Erreur base de données."),
    }
}

/// POST /api/admin/devices/{id}/approve → 200
///
/// Approuve un appareil en attente. Enregistre quel admin a approuvé et quand.
/// Après approbation, l'utilisateur propriétaire peut se connecter depuis cet appareil.
pub async fn admin_approve_device(
    State(s): State<AppState>,
    headers: HeaderMap,
    Path(device_id): Path<Uuid>,
) -> Response {
    let admin = match auth_admin(&s.db, &headers).await {
        Ok(u) => u,
        Err(e) => return e,
    };
    let result = sqlx::query(
        // approved_by enregistre quel admin a approuvé → traçabilité
        "UPDATE devices
         SET approved = true, approved_at = NOW(), approved_by = $1
         WHERE id = $2 AND revoked = false",
    )
    .bind(admin.id).bind(device_id).execute(&s.db).await;

    match result {
        Ok(r) if r.rows_affected() == 0 => {
            error_response(StatusCode::NOT_FOUND, "Appareil introuvable ou déjà révoqué.")
        }
        Ok(_) => {
            audit_log(&s.db, Some(admin.id), "device_approved", Some(device_id), Some("device"), None, None, None).await;
            Json(ApiMessage { message: "Appareil approuvé.".into() }).into_response()
        }
        Err(_) => error_response(StatusCode::INTERNAL_SERVER_ERROR, "Erreur base de données."),
    }
}

/// POST /api/admin/devices/{id}/revoke → 200
///
/// Révoque un appareil ET toutes les sessions ouvertes sur cet appareil.
/// L'utilisateur sera immédiatement déconnecté de tous les onglets/navigateurs
/// utilisant cet appareil.
pub async fn admin_revoke_device(
    State(s): State<AppState>,
    headers: HeaderMap,
    Path(device_id): Path<Uuid>,
) -> Response {
    let admin = match auth_admin(&s.db, &headers).await {
        Ok(u) => u,
        Err(e) => return e,
    };
    // D'abord révoquer les sessions pour déconnecter l'utilisateur immédiatement
    let _ = sqlx::query("UPDATE sessions SET revoked = true WHERE device_id = $1")
        .bind(device_id).execute(&s.db).await;

    let result = sqlx::query("UPDATE devices SET revoked = true WHERE id = $1")
        .bind(device_id).execute(&s.db).await;

    match result {
        Ok(r) if r.rows_affected() == 0 => error_response(StatusCode::NOT_FOUND, "Appareil introuvable."),
        Ok(_) => {
            audit_log(&s.db, Some(admin.id), "device_revoked", Some(device_id), Some("device"), None, None, None).await;
            Json(ApiMessage { message: "Appareil révoqué et sessions associées fermées.".into() }).into_response()
        }
        Err(_) => error_response(StatusCode::INTERNAL_SERVER_ERROR, "Erreur base de données."),
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// ADMINISTRATION — JOURNAUX D'AUDIT
// ══════════════════════════════════════════════════════════════════════════════

/// GET /api/admin/logs?page=1&limit=50 → {"total", "page", "limit", "logs": [...]}
///
/// Retourne le journal d'audit paginé, du plus récent au plus ancien.
/// Paramètres : page (défaut 1), limit (défaut 50, max 200).
pub async fn admin_list_logs(
    State(s): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<PaginationParams>, // Axum parse les query params automatiquement
) -> Response {
    if let Err(e) = auth_admin(&s.db, &headers).await {
        return e;
    }
    // Clamp des paramètres de pagination pour éviter les abus
    let page = params.page.unwrap_or(1).max(1);
    let limit = params.limit.unwrap_or(50).min(200).max(1);
    let offset = (page - 1) * limit;

    // Nombre total d'entrées (pour permettre au frontend de calculer le nombre de pages)
    let total: i64 = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM audit_logs")
        .fetch_one(&s.db).await.unwrap_or(0);

    match sqlx::query_as::<_, LogRow>(
        "SELECT l.id, u.email AS user_email, l.action, l.target_id, l.target_type,
                l.ip_address, l.user_agent, l.details, l.created_at
         FROM audit_logs l
         LEFT JOIN users u ON u.id = l.user_id
         ORDER BY l.created_at DESC
         LIMIT $1 OFFSET $2",
    )
    .bind(limit).bind(offset).fetch_all(&s.db).await
    {
        Ok(logs) => Json(serde_json::json!({
            "total": total,
            "page": page,
            "limit": limit,
            "logs": logs,
        })).into_response(),
        Err(_) => error_response(StatusCode::INTERNAL_SERVER_ERROR, "Erreur base de données."),
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// POUR AJOUTER VOS PROPRES ENDPOINTS
// ══════════════════════════════════════════════════════════════════════════════
//
// Exemple : endpoint protégé qui retourne les données de votre application
//
// pub async fn mes_scores(State(s): State<AppState>, headers: HeaderMap) -> Response {
//     // 1. Vérifier l'authentification
//     let auth = match auth_session(&s.db, &headers).await {
//         Ok(u) => u,
//         Err(e) => return e,
//     };
//
//     // 2. Votre logique métier
//     let scores = sqlx::query_as::<_, MonScore>(
//         "SELECT * FROM scores WHERE user_id = $1 ORDER BY date DESC",
//     )
//     .bind(auth.id)
//     .fetch_all(&s.db)
//     .await;
//
//     // 3. Retourner la réponse
//     match scores {
//         Ok(data) => Json(data).into_response(),
//         Err(_) => error_response(StatusCode::INTERNAL_SERVER_ERROR, "Erreur base de données."),
//     }
// }
