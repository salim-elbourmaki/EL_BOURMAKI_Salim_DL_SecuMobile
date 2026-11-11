/**
 * src/config.ts
 *
 * Configuration sécurisée de l'application.
 *
 * ═══════════════════════════════════════════════════════════════
 * CORRECTIONS vs CODE VULNÉRABLE (config.js) :
 * ═══════════════════════════════════════════════════════════════
 *
 * 1. API_URL :
 *    AVANT : "http://api.santeplus.ma/v1" (HTTP en clair — vuln #1)
 *    APRÈS : "https://api.santeplus.ma/v1" (HTTPS obligatoire)
 *            ou injection via EXPO_PUBLIC_API_URL
 *
 * 2. MAPS_API_KEY :
 *    AVANT : "AIzaSyD-santeplus-cle-prod-4f9a2b" en dur (vuln #2)
 *    APRÈS : SUPPRIMÉE du code client !
 *            La cartographie passe par le proxy backend :
 *            GET /v1/maps/geocode (cf. server/server.js)
 *            La clé reste sur le serveur, JAMAIS dans l'APK/IPA.
 *
 * 3. DEBUG :
 *    AVANT : export const DEBUG = true; en dur (vuln #3)
 *    APRÈS : __DEV__ natif de React Native
 *            __DEV__ est automatiquement true en dev, false en prod
 * ═══════════════════════════════════════════════════════════════
 */

// ── URL de l'API (HTTPS OBLIGATOIRE) ─────────────────────────
// EXPO_PUBLIC_* est injectée au build par Expo. Ce n'est PAS un secret
// (les URLs d'API sont visibles dans le trafic réseau de toute façon).
// En production, TOUJOURS HTTPS. Le HTTP est strictement interdit.
export const API_URL =
  process.env.EXPO_PUBLIC_API_URL || "https://api.santeplus.ma/v1";

// ── Flag de débogage sécurisé ─────────────────────────────────
// On n'utilise PLUS une variable booléenne en dur comme DEBUG = true.
// __DEV__ est une variable globale fournie par le moteur JS de React Native :
// - true  lorsque l'application tourne via "expo start" / Metro
// - false dès que l'application est compilée pour release / production
// Cela garantit qu'aucun log sensible ne fuite en production.
export const IS_DEBUG = __DEV__;

// ── Domaine autorisé pour les WebViews et Deep Links ─────────
export const ALLOWED_DOMAIN = "santeplus.ma";
export const ALLOWED_WEBVIEW_ORIGINS = [`https://${ALLOWED_DOMAIN}`];

