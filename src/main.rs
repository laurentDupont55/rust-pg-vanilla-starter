// ── Point d'entrée de l'application ──────────────────────────────────────────
//
// Ce fichier contient uniquement le "bootstrap" : configuration, connexion DB,
// définition du router et démarrage du serveur. Toute la logique métier est
// dans les modules séparés.
//
// STRUCTURE DU PROJET :
//   src/main.rs      → démarrage, router HTTP
//   src/state.rs     → AppState (ressources partagées entre handlers)
//   src/auth.rs      → crypto, cookies, vérification de session, audit log
//   src/handlers.rs  → handlers HTTP (toute la logique métier)
//   migrations/      → fichiers SQL appliqués au démarrage
//   static/          → fichiers servis directement (HTML, CSS, JS)

mod auth;
mod handlers;
mod state;

use axum::{
    routing::{get, patch, post},
    Router,
};
use sqlx::postgres::PgPoolOptions;
use state::AppState;
use std::{env, net::SocketAddr};
use tower_http::{services::ServeDir, trace::TraceLayer};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Charge les variables d'environnement depuis le fichier .env
    // En production, préférer de vraies variables d'environnement système.
    dotenvy::dotenv().ok();

    let database_url = env::var("DATABASE_URL")?;
    let addr: SocketAddr = env::var("BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:3000".into())
        .parse()?;

    // Crée un pool de connexions PostgreSQL (max 10 connexions simultanées).
    // Un pool évite d'ouvrir/fermer une connexion à chaque requête HTTP.
    let db = PgPoolOptions::new()
        .max_connections(10)
        .connect(&database_url)
        .await?;

    // Applique automatiquement les migrations SQL du dossier ./migrations/
    // dans l'ordre alphabétique (0001_init.sql, 0002_security.sql…).
    // Les migrations déjà appliquées sont ignorées (table _sqlx_migrations en DB).
    sqlx::migrate!("./migrations").run(&db).await?;

    let state = AppState { db };

    // ── Router API ────────────────────────────────────────────────────────────
    //
    // Toutes les routes sont préfixées par /api (voir .nest("/api", api) plus bas).
    // Syntaxe Axum 0.8 : les paramètres de route utilisent {id} et non :id.
    //
    // POUR AJOUTER UNE ROUTE :
    //   1. Écrire le handler dans src/handlers.rs
    //   2. Ajouter la ligne .route(...) ici
    //   3. Redémarrer l'application (cargo run)
    let api = Router::new()
        // ── Santé ─────────────────────────────────────────────────────────
        .route("/health", get(handlers::health))

        // ── Authentification ──────────────────────────────────────────────
        .route("/register",    post(handlers::register))   // Créer un compte
        .route("/login",       post(handlers::login))      // Ouvrir une session
        .route("/me",          get(handlers::me))          // Profil de l'utilisateur connecté
        .route("/logout",      post(handlers::logout))     // Fermer la session courante
        .route("/logout-all",  post(handlers::logout_all)) // Fermer toutes ses sessions

        // ── Gestion des sessions ──────────────────────────────────────────
        .route("/sessions",              get(handlers::list_sessions))   // Mes sessions actives
        .route("/sessions/{id}/revoke",  post(handlers::revoke_session)) // Révoquer une session

        // ── Administration — utilisateurs (rôle admin requis) ─────────────
        .route("/admin/users",      get(handlers::admin_list_users))    // Liste tous les users
        .route("/admin/users/{id}", patch(handlers::admin_update_user)) // Modifie un user

        // ── Administration — appareils (rôle admin requis) ────────────────
        .route("/admin/devices",              get(handlers::admin_list_devices))
        .route("/admin/devices/{id}/approve", post(handlers::admin_approve_device))
        .route("/admin/devices/{id}/revoke",  post(handlers::admin_revoke_device))

        // ── Administration — journaux (rôle admin requis) ─────────────────
        .route("/admin/logs", get(handlers::admin_list_logs)) // ?page=1&limit=50

        .with_state(state);

    // ── Application complète ──────────────────────────────────────────────────
    //
    // On imbrique le router API sous /api.
    // Les fichiers statiques (HTML, CSS, JS) sont servis en fallback depuis ./static/.
    // TraceLayer ajoute des logs HTTP (méthode, URL, durée, statut).
    let app = Router::new()
        .nest("/api", api)
        .fallback_service(ServeDir::new("static"))
        .layer(TraceLayer::new_for_http());

    println!("Application disponible sur http://{addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
