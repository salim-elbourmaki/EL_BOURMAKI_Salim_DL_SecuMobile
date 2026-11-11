/**
 * src/services/auth.ts
 *
 * Service d'authentification sécurisé.
 *
 * ═══════════════════════════════════════════════════════════════
 * CORRECTIONS vs CODE VULNÉRABLE (auth.js) :
 * ═══════════════════════════════════════════════════════════════
 *
 * ┌─────────────────────────┬──────────────────────────────────┐
 * │ Code vulnérable         │ Code corrigé                     │
 * ├─────────────────────────┼──────────────────────────────────┤
 * │ GET /login?email=&pass= │ POST /login + body JSON          │
 * │ HTTP (texte clair)      │ HTTPS (chiffré TLS)              │
 * │ AsyncStorage("token")   │ expo-secure-store (Keychain/KS)  │
 * │ AsyncStorage("password")│ ❌ SUPPRIMÉ — refresh token      │
 * │ console.log(data)       │ __DEV__ + masquage               │
 * │ isAdmin() côté client   │ ❌ SUPPRIMÉ — RBAC côté serveur  │
 * └─────────────────────────┴──────────────────────────────────┘
 * ═══════════════════════════════════════════════════════════════
 */

import { saveTokens, clearTokens } from "./secureStorage";

const API_BASE_URL =
  process.env.EXPO_PUBLIC_API_URL || "https://api.santeplus.ma/v1";

/** Structure de la réponse serveur pour POST /v1/login */
interface LoginResponse {
  accessToken: string;
  refreshToken: string;
  user: {
    id: string;
    name: string;
    email: string;
  };
}

/**
 * Authentifie l'utilisateur de manière sécurisée.
 *
 * @param email    - Adresse e-mail du patient/médecin
 * @param password - Mot de passe (transmis en HTTPS, JAMAIS stocké)
 * @returns Les informations publiques de l'utilisateur
 *
 * ═══════════════════════════════════════════════════════════════
 * MENACES COUVERTES :
 *
 * M5 — Insecure Communication :
 *   AVANT : fetch(`http://...?email=${email}&password=${password}`)
 *     → GET : les credentials sont dans l'URL, visible en clair
 *     → HTTP : aucun chiffrement en transit
 *   APRÈS : fetch("https://...", { method: "POST", body: JSON.stringify({...}) })
 *     → POST : les credentials sont dans le body, chiffré par TLS
 *     → HTTPS : chiffrement bout-en-bout
 *
 * M9 — Insecure Data Storage :
 *   AVANT : AsyncStorage.setItem("password", password)
 *     → Mot de passe en texte brut sur le système de fichiers
 *   APRÈS : saveTokens(accessToken, refreshToken) via expo-secure-store
 *     → Tokens (pas le mot de passe) dans le Keychain/Keystore hardware
 *
 * M1 — Improper Credential Usage :
 *   AVANT : console.log("Login OK", data) avec DEBUG = true
 *     → Fuite du token dans les logs système (logcat, Xcode)
 *   APRÈS : __DEV__ (false en production) + aucune donnée sensible
 * ═══════════════════════════════════════════════════════════════
 */
export async function login(
  email: string,
  password: string
): Promise<LoginResponse["user"]> {
  // ── Requête POST en HTTPS ──────────────────────────────────
  // Pourquoi POST et pas GET ?
  // - GET : les paramètres sont dans l'URL → loguées par les serveurs web,
  //   caches proxy, CDN, et visibles dans l'historique du navigateur
  // - POST : les paramètres sont dans le body → chiffrés par TLS,
  //   non loguées par défaut, non cachées, non dans l'historique
  const response = await fetch(`${API_BASE_URL}/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.error || "Échec de la connexion");
  }

  const data: LoginResponse = await response.json();

  // ── Stockage SÉCURISÉ des tokens UNIQUEMENT ────────────────
  // On ne stocke JAMAIS le mot de passe :
  // - Un mot de passe compromis est utilisable immédiatement et indéfiniment
  // - Un refresh token est révocable côté serveur et a une durée de vie limitée
  await saveTokens(data.accessToken, data.refreshToken);

  // ── Logs sécurisés ─────────────────────────────────────────
  if (__DEV__) {
    // __DEV__ est un booléen natif de React Native :
    // - true en mode développement (expo start)
    // - false automatiquement dans les builds de production (expo build)
    // Contrairement à DEBUG = true dans config.js qui est TOUJOURS true
    console.log(`[Auth] ✅ Connexion réussie : ${data.user.email}`);
    // ⛔ INTERDIT même en __DEV__ :
    // console.log(data.accessToken)  → capturé par adb logcat
    // console.log(password)          → capturé par Xcode console
    // console.log(data)              → contient les tokens
  }

  return data.user;
}

/**
 * Déconnecte l'utilisateur en supprimant tous les tokens du stockage sécurisé.
 */
export async function logout(): Promise<void> {
  await clearTokens();
  if (__DEV__) {
    console.log("[Auth] 🔒 Déconnexion — tous les tokens supprimés");
  }
}

/**
 * ═══════════════════════════════════════════════════════════════
 * POURQUOI isAdmin() N'EXISTE PLUS CÔTÉ CLIENT
 * ═══════════════════════════════════════════════════════════════
 *
 * Code vulnérable (auth.js L13-15) :
 * ```
 *   export async function isAdmin() {
 *     const role = await AsyncStorage.getItem("role");
 *     return role === "admin";
 *   }
 * ```
 *
 * FAILLE : M3 — Insecure Authorization
 *
 * DÉMONSTRATION TECHNIQUE DE LA FAILLE :
 * ──────────────────────────────────────
 * 1. Via ADB (appareil rooté) :
 *    $ adb shell run-as com.santeplus
 *    $ sqlite3 databases/RKStorage
 *    > UPDATE catalystLocalStorage SET value='"admin"' WHERE key='"role"';
 *    → isAdmin() retourne maintenant true pour un simple patient
 *
 * 2. Via Frida (instrumentation dynamique) :
 *    Frida.attach("com.santeplus")
 *    Interceptor.attach(Module.findExportByName(null, "getItem"), {
 *      onLeave: function(retval) {
 *        if (this.key === "role") retval.replace(Memory.allocUtf8String("admin"));
 *      }
 *    });
 *    → Chaque appel getItem("role") retourne "admin"
 *
 * SOLUTION — RBAC CÔTÉ SERVEUR :
 * ──────────────────────────────
 * Le rôle est une CLAIM signée dans le JWT :
 *   { userId: "u1", role: "patient", iat: ..., exp: ... }
 *
 * Signé avec JWT_SECRET côté serveur → le client NE PEUT PAS
 * modifier le rôle sans invalider la signature HMAC.
 *
 * Le middleware authenticateToken() du serveur vérifie :
 *   jwt.verify(token, JWT_SECRET) → extrait req.user.role
 *
 * L'endpoint /rdv/:id vérifie ensuite :
 *   if (req.user.role !== "admin" && rdv.userId !== req.user.userId)
 *     → 403 Forbidden
 *
 * → Le contrôle est INCONTOURNABLE car exécuté côté serveur.
 * ═══════════════════════════════════════════════════════════════
 */

