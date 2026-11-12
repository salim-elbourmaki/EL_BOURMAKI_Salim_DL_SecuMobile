// server/server.js — Mock Backend SantéPlus Secure
// ═══════════════════════════════════════════════════════════════
// Ce serveur Express simule l'API REST sécurisée pour la démonstration.
// En production, ce serait un backend complet (NestJS, Django, Spring Boot)
// avec une vraie base de données et des mots de passe hachés (bcrypt/argon2).
// ═══════════════════════════════════════════════════════════════

const express = require("express");
const jwt = require("jsonwebtoken");
const cors = require("cors");
require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json()); // Parse le body JSON (pas de query strings pour les credentials)

// ── Configuration via variables d'environnement (JAMAIS en dur) ──
const JWT_SECRET = process.env.JWT_SECRET || "dev-only-secret-32-chars-min!!!";
const ACCESS_TOKEN_EXPIRY = "15m";  // 15 minutes — limite la fenêtre d'exploitation si volé
const REFRESH_TOKEN_EXPIRY = "7d";  // 7 jours — stocké dans le Keychain/Keystore
const PORT = process.env.PORT || 3000;

// ── Base de données simulée ───────────────────────────────────
// En production : mots de passe hachés avec bcrypt (coût >= 12)
const USERS = [
  {
    id: "u1",
    email: "patient@santeplus.ma",
    password: "P@ssw0rd123", // En prod : bcrypt.hashSync("P@ssw0rd123", 12)
    role: "patient",
    name: "Karim Benali",
  },
  {
    id: "u2",
    email: "admin@santeplus.ma",
    password: "Adm1n$ecure",
    role: "admin",
    name: "Dr. Amina Tazi",
  },
];

const RENDEZ_VOUS = [
  {
    id: "550e8400-e29b-41d4-a716-446655440000",
    userId: "u1",
    medecin: "Dr. Tazi",
    date: "2026-12-01T10:00:00Z",
    motif: "Consultation générale",
  },
  {
    id: "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
    userId: "u2",
    medecin: "Dr. Fassi",
    date: "2026-12-05T14:30:00Z",
    motif: "Suivi cardiologie",
  },
];

const ORDONNANCES = [
  {
    id: "ord-001",
    userId: "u1",
    date: "2026-11-15",
    medecin: "Tazi",
    medicaments: ["Amoxicilline 1g — 2x/jour", "Paracétamol 500mg — si douleur"],
  },
];

// ═══════════════════════════════════════════════════════════════
// MIDDLEWARE : Vérification du token JWT (Authorization: Bearer)
// ═══════════════════════════════════════════════════════════════
// MENACE COUVERTE : M3 — Insecure Authentication
// Le token est vérifié à CHAQUE requête protégée. La signature JWT
// garantit que le payload (userId, role) n'a pas été modifié par le client.
function authenticateToken(req, res, next) {
  // ── Le token DOIT être dans le header Authorization ──
  // Jamais dans l'URL (visible dans les logs serveur, caches, Referer)
  const authHeader = req.headers["authorization"];
  const token =
    authHeader && authHeader.startsWith("Bearer ")
      ? authHeader.split(" ")[1]
      : null;

  if (!token) {
    return res.status(401).json({ error: "Token manquant. Authentification requise." });
  }

  try {
    // jwt.verify() vérifie à la fois la SIGNATURE et l'EXPIRATION
    // Si le token a été modifié (ex: rôle changé), la signature est invalide
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // { userId, email, role, iat, exp }
    next();
  } catch (err) {
    if (err.name === "TokenExpiredError") {
      return res.status(401).json({ error: "Token expiré. Utilisez le refresh token." });
    }
    return res.status(403).json({ error: "Token invalide." });
  }
}

// ═══════════════════════════════════════════════════════════════
// POST /v1/login — Authentification sécurisée
// ═══════════════════════════════════════════════════════════════
// CORRECTIONS vs code vulnérable :
// - POST (pas GET) : les identifiants sont dans le body, pas dans l'URL
// - Le body est chiffré par TLS (HTTPS), les query params ne le sont pas
//   au niveau des logs serveur
// - On retourne 2 tokens : access (court) + refresh (long)
// - On ne retourne JAMAIS le mot de passe ni le rôle exploitable
app.post("/v1/login", (req, res) => {
  const { email, password } = req.body; // ← body JSON, pas query string

  if (!email || !password) {
    return res.status(400).json({ error: "Email et mot de passe requis dans le body JSON." });
  }

  const user = USERS.find((u) => u.email === email && u.password === password);
  if (!user) {
    // Message générique : ne pas révéler si c'est l'email ou le mot de passe qui est faux
    // (empêche l'énumération de comptes)
    return res.status(401).json({ error: "Identifiants incorrects." });
  }

  // ── Le rôle est SIGNÉ dans le JWT par le serveur ──
  // Le client ne peut PAS le modifier sans invalider la signature
  // C'est la solution à la faille isAdmin() côté client (vuln #8)
  const accessToken = jwt.sign(
    { userId: user.id, email: user.email, role: user.role },
    JWT_SECRET,
    { expiresIn: ACCESS_TOKEN_EXPIRY }
  );

  const refreshToken = jwt.sign(
    { userId: user.id, type: "refresh" },
    JWT_SECRET,
    { expiresIn: REFRESH_TOKEN_EXPIRY }
  );

  res.json({
    accessToken,
    refreshToken,
    user: { id: user.id, name: user.name, email: user.email },
    // ⛔ PAS de : password, role, ou données sensibles
  });
});

// ═══════════════════════════════════════════════════════════════
// POST /v1/refresh — Rafraîchissement du token d'accès
// ═══════════════════════════════════════════════════════════════
// Permet la reconnexion automatique SANS stocker le mot de passe.
// Le refresh token est stocké dans expo-secure-store (Keychain/Keystore).
app.post("/v1/refresh", (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(400).json({ error: "Refresh token requis." });
  }

  try {
    const decoded = jwt.verify(refreshToken, JWT_SECRET);

    // Vérifier que c'est bien un refresh token (pas un access token réutilisé)
    if (decoded.type !== "refresh") {
      return res.status(403).json({ error: "Type de token invalide." });
    }

    const user = USERS.find((u) => u.id === decoded.userId);
    if (!user) {
      return res.status(404).json({ error: "Utilisateur introuvable." });
    }

    const newAccessToken = jwt.sign(
      { userId: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: ACCESS_TOKEN_EXPIRY }
    );

    res.json({ accessToken: newAccessToken });
  } catch (err) {
    return res.status(403).json({ error: "Refresh token invalide ou expiré." });
  }
});

// ═══════════════════════════════════════════════════════════════
// GET /v1/rdv/:id — Consultation d'un rendez-vous (protégé)
// ═══════════════════════════════════════════════════════════════
// CORRECTIONS :
// - Token dans le header (pas dans l'URL)
// - Validation UUID de l'ID (empêche path traversal, injection)
// - Contrôle d'accès RBAC côté serveur (pas côté client)
app.get("/v1/rdv/:id", authenticateToken, (req, res) => {
  const { id } = req.params;

  // ── Validation du format UUID ──
  // Empêche les injections : ../../admin, <script>, 1 OR 1=1
  const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  if (!UUID_REGEX.test(id)) {
    return res.status(400).json({ error: "Format d'identifiant invalide. UUID attendu." });
  }

  const rdv = RENDEZ_VOUS.find((r) => r.id === id);
  if (!rdv) {
    return res.status(404).json({ error: "Rendez-vous introuvable." });
  }

  // ── CONTRÔLE D'ACCÈS RBAC CÔTÉ SERVEUR ──
  // C'est ICI que le contrôle de rôle se fait, PAS côté client.
  // Le rôle est lu depuis le JWT signé (req.user.role), pas depuis AsyncStorage.
  // Un patient ne peut voir QUE ses propres rendez-vous.
  // Un admin peut voir tous les rendez-vous.
  if (req.user.role !== "admin" && rdv.userId !== req.user.userId) {
    return res.status(403).json({
      error: "Accès interdit. Ce rendez-vous ne vous appartient pas.",
    });
  }

  res.json(rdv);
});

// ═══════════════════════════════════════════════════════════════
// GET /v1/ordonnances — Liste des ordonnances du patient connecté
// ═══════════════════════════════════════════════════════════════
app.get("/v1/ordonnances", authenticateToken, (req, res) => {
  // Filtrage par userId du token JWT — isolation des données
  const userOrdonnances =
    req.user.role === "admin"
      ? ORDONNANCES
      : ORDONNANCES.filter((o) => o.userId === req.user.userId);

  res.json(userOrdonnances);
});

// ═══════════════════════════════════════════════════════════════
// GET /v1/maps/geocode — Proxy sécurisé pour Google Maps (BONUS)
// ═══════════════════════════════════════════════════════════════
// MENACE COUVERTE : M1 — Improper Credential Usage
// La clé Google Maps reste CÔTÉ SERVEUR et n'est jamais envoyée au client.
// Le client appelle notre proxy, qui ajoute la clé et transfère à Google.
//
// RESTRICTIONS SUPPLÉMENTAIRES (Google Cloud Console) :
// 1. Restriction par application :
//    - Android : SHA-256 du certificat de signature + package name
//    - iOS : Bundle ID
// 2. Restriction par API : activer uniquement Geocoding API
// 3. Quotas : limiter à X requêtes/jour/utilisateur
// 4. Alertes de facturation : notification si dépassement du budget
app.get("/v1/maps/geocode", authenticateToken, async (req, res) => {
  const { address } = req.query;

  // Validation de l'entrée
  if (!address || typeof address !== "string" || address.length > 200) {
    return res.status(400).json({ error: "Paramètre 'address' invalide (max 200 caractères)." });
  }

  const MAPS_KEY = process.env.GOOGLE_MAPS_API_KEY; // ← Depuis .env serveur
  if (!MAPS_KEY) {
    return res.status(500).json({ error: "Clé Maps non configurée côté serveur." });
  }

  try {
    const url = `https://maps.googleapis.com/maps/api/geocode/json?address=${encodeURIComponent(address)}&key=${MAPS_KEY}`;
    const response = await fetch(url);
    const data = await response.json();
    res.json(data);
  } catch (err) {
    res.status(502).json({ error: "Erreur du service de cartographie." });
  }
});

// ── Démarrage ─────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`✅ SantéPlus Mock API — http://localhost:${PORT}`);
  console.log(`   POST /v1/login        — Authentification`);
  console.log(`   POST /v1/refresh       — Rafraîchir le token`);
  console.log(`   GET  /v1/rdv/:id       — Consulter un RDV`);
  console.log(`   GET  /v1/ordonnances   — Lister les ordonnances`);
  console.log(`   GET  /v1/maps/geocode  — Proxy Google Maps (Bonus)`);
});

