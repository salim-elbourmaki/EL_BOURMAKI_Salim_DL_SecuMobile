/**
 * src/services/api.ts
 *
 * Client API sécurisé avec intercepteur Bearer et rafraîchissement automatique.
 *
 * ═══════════════════════════════════════════════════════════════
 * MENACES COUVERTES :
 * ═══════════════════════════════════════════════════════════════
 *
 * M5 — Insecure Communication :
 *   → Toutes les requêtes passent en HTTPS (plus jamais HTTP)
 *   → L'URL de base est https://api.santeplus.ma/v1
 *
 * M1 — Improper Credential Usage :
 *   → Le token est dans le header Authorization: Bearer <token>
 *   → JAMAIS dans l'URL (les URLs sont loguées par les serveurs,
 *     proxies, CDN, et visibles dans l'en-tête Referer)
 *
 * M8 — Security Misconfiguration :
 *   → Logs conditionnels (__DEV__ uniquement — false en production)
 *   → Aucune donnée sensible dans les logs, même en développement
 * ═══════════════════════════════════════════════════════════════
 */

import {
  getAccessToken,
  getRefreshToken,
  saveTokens,
  clearTokens,
} from "./secureStorage";

// ── URL de base ───────────────────────────────────────────────
// EXPO_PUBLIC_API_URL est injectée au build via le fichier .env
// Ce n'est PAS un secret (c'est une URL publique, visible dans le trafic réseau)
// Les vrais secrets (JWT_SECRET, MAPS_KEY) restent côté serveur
const API_BASE_URL =
  process.env.EXPO_PUBLIC_API_URL || "https://api.santeplus.ma/v1";

// Flag anti-boucle pour éviter les rafraîchissements récursifs infinis
let isRefreshing = false;

/**
 * Effectue une requête API authentifiée.
 *
 * Flux sécurisé :
 * ┌─────────────────┐
 * │ 1. Lire token   │ ← depuis expo-secure-store (Keychain/Keystore)
 * │    du Keychain   │
 * └────────┬────────┘
 *          ▼
 * ┌─────────────────┐
 * │ 2. Requête HTTPS│ ← Authorization: Bearer <token>
 * │    avec Bearer   │   (header, PAS dans l'URL)
 * └────────┬────────┘
 *          ▼
 * ┌─────────────────┐    ┌──────────────────┐
 * │ 3. Réponse OK ? │─No→│ 4. Rafraîchir    │
 * │    (200)        │    │    le token       │
 * └────────┬────────┘    └────────┬─────────┘
 *          │                      │
 *     Yes  ▼                      ▼
 * ┌─────────────────┐    ┌──────────────────┐
 * │ Retourner data  │    │ Re-tenter requête│
 * └─────────────────┘    └──────────────────┘
 *
 * @param endpoint - Chemin de l'API (ex: "/rdv/uuid-ici")
 * @param options  - Options fetch (method, body, headers additionnels)
 * @returns La réponse JSON parsée
 * @throws Error("SESSION_EXPIRED") si le rafraîchissement échoue
 */
export async function apiRequest<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const accessToken = await getAccessToken();

  const headers: HeadersInit = {
    "Content-Type": "application/json",
    ...(options.headers || {}),
    // ── Token dans le header Authorization ──
    // C'est la méthode standard et sécurisée (RFC 6750)
    // Contrairement au query string ?token=..., le header n'apparaît pas
    // dans les logs serveur, l'historique, les caches, ou l'en-tête Referer
    ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
  };

  const response = await fetch(`${API_BASE_URL}${endpoint}`, {
    ...options,
    headers,
  });

  // ── Gestion du token expiré (401) ───────────────────────────
  if (response.status === 401 && !isRefreshing) {
    const refreshed = await attemptTokenRefresh();
    if (refreshed) {
      // Réessayer la requête avec le nouveau token
      return apiRequest<T>(endpoint, options);
    }
    // Le refresh a échoué → déconnexion forcée
    await clearTokens();
    throw new Error("SESSION_EXPIRED");
  }

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.error || `Erreur HTTP ${response.status}`);
  }

  return response.json();
}

/**
 * Tente de rafraîchir l'access token via le refresh token.
 *
 * ═══════════════════════════════════════════════════════════════
 * POURQUOI LE REFRESH TOKEN REMPLACE LE STOCKAGE DU MOT DE PASSE :
 * ═══════════════════════════════════════════════════════════════
 * L'ancien code stockait le mot de passe pour la "reconnexion auto".
 * Le refresh token est SUPÉRIEUR car :
 * 1. Il est RÉVOCABLE côté serveur (blacklist) — un mot de passe
 *    compromis reste valide jusqu'au changement par l'utilisateur
 * 2. Il a une DURÉE DE VIE limitée (7 jours vs mot de passe permanent)
 * 3. Il ne peut PAS être utilisé sur d'autres services
 *    (un mot de passe réutilisé compromet tous les comptes)
 * ═══════════════════════════════════════════════════════════════
 */
async function attemptTokenRefresh(): Promise<boolean> {
  isRefreshing = true; // Empêche les boucles infinies de refresh

  try {
    const refreshToken = await getRefreshToken();
    if (!refreshToken) return false;

    const response = await fetch(`${API_BASE_URL}/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refreshToken }),
    });

    if (!response.ok) return false;

    const data = await response.json();
    await saveTokens(data.accessToken, refreshToken);

    // ── Logs sécurisés ────────────────────────────────────────
    if (__DEV__) {
      // __DEV__ est automatiquement false en build de production
      // Contrairement à DEBUG = true en dur dans config.js (vuln #3)
      console.log("[API] ✅ Token rafraîchi avec succès");
      // ⛔ JAMAIS : console.log(data.accessToken) → fuite dans logcat/Xcode
    }

    return true;
  } catch {
    return false;
  } finally {
    isRefreshing = false;
  }
}

