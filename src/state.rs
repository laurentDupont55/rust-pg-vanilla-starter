// ── État partagé de l'application ────────────────────────────────────────────
//
// AppState est cloné et injecté dans chaque handler par Axum via `State<AppState>`.
// Il contient les ressources "globales" : ici uniquement le pool de connexions DB.
//
// Pour ajouter une ressource partagée (client HTTP, cache, config…) :
//   1. Ajouter un champ ici
//   2. L'initialiser dans main.rs avant la construction du router
//
// Axum exige que AppState soit Clone + Send + Sync.
// PgPool est lui-même un pool thread-safe, donc Clone est peu coûteux (c'est un Arc).

use sqlx::PgPool;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
}
