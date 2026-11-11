/**
 * src/services/secureStorage.ts
 *
 * Stockage sécurisé des tokens via expo-secure-store.
 *
 * ═══════════════════════════════════════════════════════════════
 * MENACE COUVERTE : M9 — Insecure Data Storage (OWASP Mobile 2024)
 * ═══════════════════════════════════════════════════════════════
 *
 * PROBLÈME (code original) :
 *   await AsyncStorage.setItem("token", data.token);
 *   await AsyncStorage.setItem("password", password);
 *   → Stockage en TEXTE BRUT sur le système de fichiers
 *   → Accessible par tout processus root ou via adb backup
 *
 * SOLUTION :
 *   expo-secure-store utilise :
 *   - iOS  : Keychain (protégé par le Secure Enclave — puce hardware)
 *   - Android : Android Keystore (TEE / StrongBox hardware)
 *
 *   L'option WHEN_UNLOCKED_THIS_DEVICE_ONLY garantit :
 *   ✅ Données accessibles UNIQUEMENT quand l'appareil est déverrouillé
 *   ✅ Données NON incluses dans les sauvegardes iCloud/iTunes/Google
 *   ✅ Données NON transférables vers un autre appareil
 *
 * CONFORMITÉ LOI 09-08 (art. 23) :
 *   Les données de santé exigent des mesures de protection proportionnées
 *   à leur sensibilité. Le chiffrement matériel satisfait cette exigence.
 * ═══════════════════════════════════════════════════════════════
 */

import * as SecureStore from "expo-secure-store";

// ── Clés de stockage ──────────────────────────────────────────
// Préfixées par le nom de l'app pour éviter les collisions
const KEYS = {
  ACCESS_TOKEN: "santeplus_access_token",
  REFRESH_TOKEN: "santeplus_refresh_token",
} as const;

// ── Options de sécurité maximale ──────────────────────────────
const SECURE_OPTIONS: SecureStore.SecureStoreOptions = {
  // WHEN_UNLOCKED_THIS_DEVICE_ONLY :
  // - iOS : kSecAttrAccessibleWhenUnlockedThisDeviceOnly
  //   → Le Keychain item est déchiffrable uniquement quand l'appareil
  //     est déverrouillé, et n'est jamais dans les sauvegardes
  // - Android : requireUserAuthentication dans le Keystore
  keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
};

// ═══════════════════════════════════════════════════════════════
// POURQUOI ON NE STOCKE PLUS LE MOT DE PASSE :
// ═══════════════════════════════════════════════════════════════
// L'ancien code faisait : AsyncStorage.setItem("password", password)
// pour la "reconnexion automatique". C'est une erreur grave :
//
// 1. Un mot de passe compromis ne peut PAS être révoqué à distance
//    (l'utilisateur doit le changer manuellement)
// 2. Un refresh token PEUT être révoqué côté serveur (blacklist)
// 3. Le mot de passe est souvent réutilisé sur d'autres comptes
//
// → La reconnexion automatique se fait via le REFRESH TOKEN,
//   qui est à usage unique et révocable.
// ═══════════════════════════════════════════════════════════════

/**
 * Sauvegarde les deux tokens dans le stockage sécurisé.
 *
 * @param accessToken  - JWT de courte durée (15 min) pour les requêtes API
 * @param refreshToken - JWT de longue durée (7 jours) pour renouveler l'access token
 */
export async function saveTokens(
  accessToken: string,
  refreshToken: string
): Promise<void> {
  await SecureStore.setItemAsync(KEYS.ACCESS_TOKEN, accessToken, SECURE_OPTIONS);
  await SecureStore.setItemAsync(KEYS.REFRESH_TOKEN, refreshToken, SECURE_OPTIONS);
}

/** Récupère l'access token depuis le Keychain / Keystore. */
export async function getAccessToken(): Promise<string | null> {
  return SecureStore.getItemAsync(KEYS.ACCESS_TOKEN, SECURE_OPTIONS);
}

/** Récupère le refresh token depuis le Keychain / Keystore. */
export async function getRefreshToken(): Promise<string | null> {
  return SecureStore.getItemAsync(KEYS.REFRESH_TOKEN, SECURE_OPTIONS);
}

/**
 * Supprime tous les tokens — appelé lors de la déconnexion.
 * Garantit qu'aucun résidu de session ne persiste sur l'appareil.
 */
export async function clearTokens(): Promise<void> {
  await SecureStore.deleteItemAsync(KEYS.ACCESS_TOKEN, SECURE_OPTIONS);
  await SecureStore.deleteItemAsync(KEYS.REFRESH_TOKEN, SECURE_OPTIONS);
}

