// ── Frontend Vanilla JS ────────────────────────────────────────────────────────
//
// Architecture : SPA (Single Page Application) minimaliste.
// Pas de framework — uniquement le DOM natif et fetch().
//
// STRUCTURE DE LA PAGE :
//   #loading          → spinner affiché pendant la vérification de session au chargement
//   #login-section    → formulaire de connexion
//   #dashboard-section→ tableau de bord de l'utilisateur (sessions actives…)
//   #admin-section    → panneau d'administration (rôle admin uniquement)
//
// FLUX D'INITIALISATION :
//   1. La page charge → #loading visible, reste masqué
//   2. On appelle GET /api/me → si session valide : showApp(user), sinon : showLogin()
//   3. L'utilisateur interagit → appels API via fetch()
//
// POUR AJOUTER VOS DONNÉES APPLICATIVES :
//   Créer une nouvelle section HTML, écrire une fonction de chargement (ex: loadScores()),
//   l'appeler dans showApp() ou depuis un bouton.

/* ── Helper fetch ─────────────────────────────────────────────────────────── */

/**
 * Wrapper autour de fetch() pour toutes les requêtes API.
 * - Ajoute le header Content-Type: application/json
 * - Envoie les cookies (credentials: "same-origin")
 * - Lève une Error si la réponse HTTP n'est pas 2xx (avec le message du serveur)
 *
 * Usage :
 *   const user = await api("me");                              // GET
 *   const data = await api("login", { method:"POST", body:JSON.stringify({...}) });
 */
async function api(path, options = {}) {
  const resp = await fetch(`/api/${path}`, {
    credentials: "same-origin",   // Envoie les cookies HttpOnly dans la requête
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    // On attache le status HTTP à l'erreur pour pouvoir l'inspecter côté appelant
    throw Object.assign(new Error(data.message || `HTTP ${resp.status}`), { status: resp.status });
  }
  return data;
}

/* ── Helpers DOM ──────────────────────────────────────────────────────────── */

/** Formate une date ISO en date/heure lisible (format français). */
function fmt(date) {
  if (!date) return "—";
  return new Intl.DateTimeFormat("fr-FR", { dateStyle: "short", timeStyle: "short" }).format(new Date(date));
}

/**
 * Crée un élément HTML avec des attributs et des enfants.
 * Remplace document.createElement + setAttribute + append dans les boucles.
 *
 * Usage :
 *   el("button", { class: "btn-primary", onclick: () => alert("!") }, "Cliquer")
 *   el("span", { class: "badge" }, "Texte")
 *
 * Attributs spéciaux :
 *   - "class" → e.className
 *   - "on*"   → handler d'événement (onclick, oninput…)
 *   - true    → setAttribute(k, "")  (attributs booléens comme disabled)
 *   - false/null/undefined → attribut ignoré
 */
function el(tag, attrs = {}, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") e.className = v;
    else if (k.startsWith("on")) e[k] = v;
    else if (v === true) e.setAttribute(k, "");
    else e.setAttribute(k, v);
  }
  for (const c of children) {
    if (c == null) continue;
    e.append(typeof c === "string" ? document.createTextNode(c) : c);
  }
  return e;
}

/** Badge coloré pour le statut d'un appareil. */
function statusBadge(approved, revoked) {
  if (revoked)   return el("span", { class: "badge badge-revoked" }, "Révoqué");
  if (!approved) return el("span", { class: "badge badge-pending" }, "En attente");
  return el("span", { class: "badge badge-ok" }, "Approuvé");
}

/** Badge coloré pour le rôle utilisateur. */
function roleBadge(role) {
  return el("span", { class: `badge badge-${role}` }, role);
}

/** Crée un tableau HTML à partir d'en-têtes et de lignes <tr>. */
function makeTable(cols, rows) {
  const thead = el("thead", {}, el("tr", {}, ...cols.map(c => el("th", {}, c))));
  const tbody = el("tbody", {}, ...rows);
  return el("div", { class: "tbl-wrap" }, el("table", {}, thead, tbody));
}

/** Affiche/masque un message de statut sous le formulaire de connexion. */
function setStatus(elId, msg, isError = true) {
  const s = document.getElementById(elId);
  s.textContent = msg;
  s.className = `status-msg ${msg ? (isError ? "error" : "info") : ""}`;
}

/* ── État global ──────────────────────────────────────────────────────────── */

let currentUser = null;  // Utilisateur connecté, ou null
let logsPage = 1;        // Page courante du journal d'audit

/* ── Gestion de la visibilité des sections ────────────────────────────────── */

function showLoading(visible) {
  document.getElementById("loading").hidden = !visible;
}

/** Affiche le formulaire de connexion et masque le reste. */
function showLogin(msg = "", isError = true) {
  currentUser = null;
  document.getElementById("login-section").hidden = false;
  document.getElementById("dashboard-section").hidden = true;
  document.getElementById("admin-section").hidden = true;
  if (msg) setStatus("login-status", msg, isError);
}

/**
 * Affiche le tableau de bord et (si admin) le panneau d'administration.
 * Appelé après un login réussi ou après la vérification de session au chargement.
 *
 * POINT D'EXTENSION : ajouter ici l'appel de chargement de vos propres données.
 *   Ex: if (user.role === "admin") loadStats();
 *       loadMesScores();
 */
function showApp(user) {
  currentUser = user;
  document.getElementById("login-section").hidden = true;
  document.getElementById("dashboard-section").hidden = false;
  // Le panneau admin n'est visible que pour les administrateurs
  document.getElementById("admin-section").hidden = user.role !== "admin";

  // Mettre à jour l'en-tête du dashboard
  document.getElementById("dash-email").textContent = user.email;
  const roleEl = document.getElementById("dash-role");
  roleEl.textContent = user.role;
  roleEl.className = `badge badge-${user.role}`;

  loadSessions();
  if (user.role === "admin") loadDevices();
}

/* ── Sessions actives de l'utilisateur ───────────────────────────────────── */

/**
 * Charge et affiche la liste des sessions actives de l'utilisateur connecté.
 * is_current=true identifie la session du navigateur actuel.
 */
async function loadSessions() {
  const container = document.getElementById("sessions-container");
  container.textContent = "Chargement…";
  try {
    const sessions = await api("sessions");
    if (!sessions.length) { container.textContent = "Aucune session active."; return; }

    const rows = sessions.map(s => {
      const revokeBtn = el("button", {
        class: "btn-danger btn-sm",
        onclick: async () => {
          revokeBtn.disabled = true;
          try {
            await api(`sessions/${s.id}/revoke`, { method: "POST", body: "{}" });
            // Si on révoque notre propre session, le serveur efface le cookie → déconnexion
            if (s.is_current) showLogin("Déconnecté.", false);
            else loadSessions(); // Sinon, actualiser la liste
          } catch (e) { revokeBtn.disabled = false; alert(e.message); }
        },
      }, "Révoquer");

      return el("tr", {},
        el("td", {}, s.device_label,
          // Marquer visuellement la session courante
          s.is_current ? el("span", { class: "badge badge-ok", style: "margin-left:.4rem" }, "actuelle") : null),
        el("td", { class: "td-mono" }, s.device_ip || "—"),
        el("td", {}, fmt(s.created_at)),
        el("td", {}, fmt(s.expires_at)),
        el("td", { class: "td-actions" }, revokeBtn),
      );
    });
    container.replaceChildren(makeTable(["Appareil", "IP", "Créée le", "Expire le", ""], rows));
  } catch (e) {
    container.textContent = `Erreur : ${e.message}`;
  }
}

/* ── Formulaire de connexion ──────────────────────────────────────────────── */

document.getElementById("login-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  setStatus("login-status", ""); // Effacer le message précédent
  const fd = new FormData(ev.target);
  try {
    const user = await api("login", {
      method: "POST",
      body: JSON.stringify({ email: fd.get("email"), password: fd.get("password") }),
    });
    showApp(user);
  } catch (e) {
    // Cas spécial : appareil en attente d'approbation (403, pas une erreur rouge)
    const isPending = e.status === 403 && e.message.includes("attente");
    setStatus("login-status", e.message, !isPending);
  }
});

document.getElementById("btn-logout").addEventListener("click", async () => {
  await api("logout", { method: "POST", body: "{}" }).catch(() => {});
  showLogin("Vous avez été déconnecté.", false);
});

document.getElementById("btn-logout-all").addEventListener("click", async () => {
  if (!confirm("Déconnecter tous vos appareils ?")) return;
  await api("logout-all", { method: "POST", body: "{}" }).catch(() => {});
  showLogin("Toutes les sessions ont été fermées.", false);
});

/* ── Admin — Navigation par onglets ───────────────────────────────────────── */

// Chaque bouton .tab affiche/masque le div #tab-{nom} correspondant
// et charge les données au besoin.
document.querySelectorAll(".tab").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
    document.querySelectorAll(".tab-content").forEach(tc => tc.hidden = true);
    btn.classList.add("active");
    document.getElementById(`tab-${btn.dataset.tab}`).hidden = false;
    // Charger les données au clic sur l'onglet (pas au chargement de la page)
    if (btn.dataset.tab === "devices") loadDevices();
    if (btn.dataset.tab === "users")   loadUsers();
    if (btn.dataset.tab === "logs")    { logsPage = 1; loadLogs(true); }
  });
});

/* ── Admin — Appareils ────────────────────────────────────────────────────── */

/**
 * Charge la liste des appareils depuis GET /api/admin/devices.
 * Les appareils en attente apparaissent en premier (tri côté serveur).
 * Met à jour le badge "X en attente" sur l'onglet.
 */
async function loadDevices() {
  const container = document.getElementById("devices-container");
  container.textContent = "Chargement…";
  try {
    const devices = await api("admin/devices");
    const pending = devices.filter(d => !d.approved && !d.revoked);

    // Badge numérique sur l'onglet pour alerter l'admin
    const badge = document.getElementById("pending-badge");
    badge.textContent = pending.length;
    badge.hidden = pending.length === 0;

    if (!devices.length) { container.textContent = "Aucun appareil enregistré."; return; }

    const rows = devices.map(d => {
      // Bouton Approuver : désactivé si déjà approuvé ou révoqué
      const approveBtn = el("button", {
        class: "btn-success btn-sm",
        disabled: d.approved || d.revoked,
        onclick: async () => {
          approveBtn.disabled = true;
          try {
            await api(`admin/devices/${d.id}/approve`, { method: "POST", body: "{}" });
            loadDevices(); // Actualiser la liste après l'action
          } catch (e) { alert(e.message); approveBtn.disabled = false; }
        },
      }, "Approuver");

      const revokeBtn = el("button", {
        class: "btn-danger btn-sm",
        disabled: d.revoked,
        onclick: async () => {
          if (!confirm("Révoquer cet appareil et fermer ses sessions ?")) return;
          revokeBtn.disabled = true;
          try {
            await api(`admin/devices/${d.id}/revoke`, { method: "POST", body: "{}" });
            loadDevices();
          } catch (e) { alert(e.message); revokeBtn.disabled = false; }
        },
      }, "Révoquer");

      return el("tr", {},
        el("td", {}, d.user_email),
        el("td", {}, d.device_label),
        el("td", { class: "td-mono" }, d.ip_address || "—"),
        el("td", {}, fmt(d.created_at)),
        el("td", {}, fmt(d.last_seen_at)),
        el("td", {}, statusBadge(d.approved, d.revoked)),
        el("td", { class: "td-actions" }, approveBtn, revokeBtn),
      );
    });
    container.replaceChildren(makeTable(["Utilisateur", "Appareil", "IP", "Enregistré", "Vu le", "Statut", ""], rows));
  } catch (e) {
    container.textContent = `Erreur : ${e.message}`;
  }
}

document.getElementById("btn-refresh-devices").addEventListener("click", loadDevices);

/* ── Admin — Utilisateurs ─────────────────────────────────────────────────── */

async function loadUsers() {
  const container = document.getElementById("users-container");
  container.textContent = "Chargement…";
  try {
    const users = await api("admin/users");
    if (!users.length) { container.textContent = "Aucun utilisateur."; return; }

    const rows = users.map(u => {
      // On ne peut pas modifier son propre compte depuis le panneau admin
      // (protection contre le lock-out accidentel)
      const isMe = currentUser && u.id === currentUser.id;

      const toggleBtn = el("button", {
        class: u.active ? "btn-warn btn-sm" : "btn-success btn-sm",
        disabled: isMe,
        title: isMe ? "Vous ne pouvez pas désactiver votre propre compte" : "",
        onclick: async () => {
          toggleBtn.disabled = true;
          try {
            await api(`admin/users/${u.id}`, { method: "PATCH", body: JSON.stringify({ active: !u.active }) });
            loadUsers();
          } catch (e) { alert(e.message); toggleBtn.disabled = false; }
        },
      }, u.active ? "Désactiver" : "Activer");

      const otherRole = u.role === "admin" ? "user" : "admin";
      const roleBtn = el("button", {
        class: "btn-secondary btn-sm",
        disabled: isMe,
        onclick: async () => {
          if (!confirm(`Passer "${u.email}" en ${otherRole} ?`)) return;
          roleBtn.disabled = true;
          try {
            await api(`admin/users/${u.id}`, { method: "PATCH", body: JSON.stringify({ role: otherRole }) });
            loadUsers();
          } catch (e) { alert(e.message); roleBtn.disabled = false; }
        },
      }, `→ ${otherRole}`);

      return el("tr", {},
        el("td", {}, u.email, isMe ? el("span", { class: "badge badge-ok", style: "margin-left:.4rem" }, "vous") : null),
        el("td", {}, roleBadge(u.role)),
        el("td", {}, u.active
          ? el("span", { class: "badge badge-ok" }, "Actif")
          : el("span", { class: "badge badge-revoked" }, "Désactivé")),
        el("td", {}, fmt(u.created_at)),
        el("td", { class: "td-actions" }, toggleBtn, roleBtn),
      );
    });
    container.replaceChildren(makeTable(["Email", "Rôle", "Statut", "Créé le", ""], rows));
  } catch (e) {
    container.textContent = `Erreur : ${e.message}`;
  }
}

/* ── Admin — Journal d'audit ──────────────────────────────────────────────── */

/**
 * Charge les entrées du journal d'audit.
 * reset=true : recharge depuis la page 1 (nouveau contenu)
 * reset=false : charge la page suivante et l'ajoute au tableau (pagination infinie)
 */
async function loadLogs(reset = false) {
  if (reset) logsPage = 1;
  const container = document.getElementById("logs-container");
  if (reset) container.textContent = "Chargement…";
  try {
    const data = await api(`admin/logs?page=${logsPage}&limit=50`);
    const rows = data.logs.map(l => el("tr", {},
      el("td", {}, fmt(l.created_at)),
      el("td", {}, l.user_email || el("em", {}, "(supprimé)")),
      el("td", {}, el("code", {}, l.action)),
      el("td", { class: "td-mono" }, l.ip_address || "—"),
      el("td", { class: "td-mono" }, (l.user_agent || "").substring(0, 60) || "—"),
    ));

    if (reset) {
      container.replaceChildren(makeTable(["Date", "Utilisateur", "Action", "IP", "Navigateur"], rows));
    } else {
      container.querySelector("tbody").append(...rows); // Ajouter au tableau existant
    }

    // Afficher/masquer le bouton "Charger plus" selon s'il reste des pages
    const moreBtn = document.getElementById("btn-load-more-logs");
    const hasMore = logsPage * 50 < data.total;
    moreBtn.hidden = !hasMore;
    if (hasMore) logsPage++;
  } catch (e) {
    if (reset) container.textContent = `Erreur : ${e.message}`;
  }
}

document.getElementById("btn-load-more-logs").addEventListener("click", () => loadLogs(false));

/* ── Initialisation au chargement de la page ──────────────────────────────── */

// IIFE (Immediately Invoked Function Expression) async :
// vérifie si une session est déjà active (cookie app_session présent et valide).
// C'est l'équivalent d'un "auto-login" à partir du cookie existant.
(async () => {
  try {
    const user = await api("me"); // Lance GET /api/me
    showLoading(false);
    showApp(user);  // Session valide → afficher l'interface
  } catch {
    showLoading(false);
    showLogin();    // Pas de session → afficher le formulaire de connexion
  }
})();
