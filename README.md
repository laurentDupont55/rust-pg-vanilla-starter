# Rust + Axum + PostgreSQL + Vanilla JS (starter)

## Pré-requis
- Rust stable (`rustup`)
- PostgreSQL 17 local
- Une base `app_db` et un rôle `app_user`

## Démarrage
```bash
cp .env.example .env
# Éditez DATABASE_URL dans .env
cargo run
```
Visitez http://127.0.0.1:3000

## Créer un premier compte
L'endpoint `POST /api/register` accepte :
```json
{"email":"vous@example.com","password":"un-mot-de-passe-long"}
```
Exemple :
```bash
curl -i -X POST http://127.0.0.1:3000/api/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"vous@example.com","password":"change-this-password"}'
```
Puis connectez-vous dans la page d'accueil.

## Endpoints
- `GET /api/health`
- `POST /api/register`
- `POST /api/login`
- `GET /api/me`
- `POST /api/logout`

## Important avant production
Ce starter est un socle de développement, pas une application prête à exposer sur Internet :
- Ajouter limitation de débit / anti-bruteforce sur login et inscription.
- Ajouter protection CSRF (token ou stratégie stricte Origin) pour les endpoints mutatifs.
- HTTPS obligatoire en production ; cookies `Secure` derrière TLS.
- Ne pas laisser l'inscription publique ouverte si l'application est interne.
- La route register attribue le rôle `user`; créer l'admin via une procédure contrôlée.
- Ajouter validation robuste, journalisation d'audit, politique de session et révocation de device.
- Le token appareil est posé pour démonstration ; cette version n'effectue pas encore de contrôle d'appareil au login.
- La reconnaissance d'appareil par cookie reste une preuve de possession du navigateur, pas une empreinte matérielle forte.
