/**
 * src/navigation/linking.ts
 *
 * Configuration des liens profonds (deep links) sécurisée.
 *
 * ═══════════════════════════════════════════════════════════════
 * MENACES COUVERTES :
 * ═══════════════════════════════════════════════════════════════
 *
 * M4 — Insufficient Input/Output Validation :
 *   AVANT : const id = new URL(url).searchParams.get("id") → aucune validation
 *   APRÈS : regex UUID v4 stricte, rejet de tout format non conforme
 *
 * M1 — Improper Credential Usage :
 *   AVANT : fetch(`${API_URL}/rdv/${id}?token=${token}`) → token dans l'URL
 *   APRÈS : token dans le header Authorization: Bearer (via apiRequest)
 *
 * M3 — Insecure Authentication :
 *   AVANT : navigation directe sans vérification de session
 *   APRÈS : vérification du token AVANT la navigation
 *
 * LIEN HIJACKING :
 *   AVANT : schéma personnalisé santeplus:// (interceptable par un malware)
 *   APRÈS : App Links HTTPS (vérification cryptographique du domaine)
 * ═══════════════════════════════════════════════════════════════
 */

import { getAccessToken } from "../services/secureStorage";
import { apiRequest } from "../services/api";

// ═══════════════════════════════════════════════════════════════
// REGEX DE VALIDATION UUID v4
// ═══════════════════════════════════════════════════════════════
// Format : xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
//   - x = caractère hexadécimal [0-9a-f]
//   - 4 = identifie la version 4 (basée sur un nombre aléatoire)
//   - y = [89ab] = identifie la variante RFC 4122
//
// POURQUOI C'EST CRITIQUE :
// Sans validation, un attaquant peut envoyer par SMS un lien :
//   santeplus://rdv?id=../../admin/users     → path traversal
//   santeplus://rdv?id=1 OR 1=1              → injection SQL
//   santeplus://rdv?id=<script>alert(1)      → XSS potentiel
// Le regex rejette TOUT ce qui n'est pas un UUID v4 valide.
// ═══════════════════════════════════════════════════════════════
const UUID_V4_REGEX =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/**
 * Configuration du linking pour React Navigation.
 *
 * En production, on utilise UNIQUEMENT les App Links / Universal Links
 * (préfixes HTTPS). Le schéma personnalisé n'est activé qu'en dev.
 */
export const linkingConfig = {
  prefixes: [
    // ── App Links (Android) / Universal Links (iOS) ──
    // Vérification cryptographique de la propriété du domaine :
    // Android : https://santeplus.ma/.well-known/assetlinks.json
    // iOS     : https://santeplus.ma/.well-known/apple-app-site-association
    "https://santeplus.ma",
    "https://*.santeplus.ma",

    // ── Schéma personnalisé en développement UNIQUEMENT ──
    // En production, ce préfixe est RETIRÉ car il est vulnérable
    // au Link Hijacking (un malware peut enregistrer "santeplus://")
    ...(process.env.NODE_ENV === "development" ? ["santeplus://"] : []),
  ],

  config: {
    screens: {
      Rdv: "rdv/:id",
      Article: "article/:slug",
    },
  },
};

/**
 * Gestionnaire de deep link sécurisé pour les rendez-vous.
 *
 * Flux de sécurité :
 * ┌───────────────────┐
 * │ 1. Valider le     │ ← UUID v4 regex
 * │    format de l'ID │   Rejeter : traversal, injection, XSS
 * └────────┬──────────┘
 *          ▼
 * ┌───────────────────┐
 * │ 2. Vérifier la    │ ← Token existe dans le Keychain/Keystore ?
 * │    session active │   Non → rediriger vers Login
 * └────────┬──────────┘
 *          ▼
 * ┌───────────────────┐
 * │ 3. Requête API    │ ← Token dans le header Authorization: Bearer
 * │    sécurisée      │   (PAS dans l'URL — cf. vuln #10)
 * └────────┬──────────┘
 *          ▼
 * ┌───────────────────┐
 * │ 4. Navigation     │ ← Backend a vérifié l'ownership (RBAC)
 * │    vers RDV       │   403 si le rdv n'appartient pas au patient
 * └───────────────────┘
 *
 * @param id         - Identifiant du rendez-vous (doit être un UUID v4)
 * @param navigation - Objet React Navigation
 */
export async function handleDeepLink(
  id: string,
  navigation: any
): Promise<void> {
  // ── ÉTAPE 1 : Validation stricte du format UUID v4 ─────────
  if (!UUID_V4_REGEX.test(id)) {
    if (__DEV__) {
      console.warn(`[DeepLink] ⛔ ID rejeté (format invalide) : ${id}`);
    }
    // On ne navigue PAS et on ne révèle PAS le format attendu
    // (ne pas aider l'attaquant à deviner le bon format)
    return;
  }

  // ── ÉTAPE 2 : Vérification de session active ──────────────
  const token = await getAccessToken();
  if (!token) {
    if (__DEV__) {
      console.log("[DeepLink] Pas de session → redirection Login");
    }
    // On passe le deep link en paramètre pour y revenir après login
    navigation.navigate("Login", { redirect: `rdv/${id}` });
    return;
  }

  // ── ÉTAPE 3 : Requête API sécurisée ────────────────────────
  // apiRequest() injecte automatiquement Authorization: Bearer <token>
  // Le token n'apparaît JAMAIS dans l'URL (contrairement à ?token=...)
  // Le backend vérifie l'ownership : 403 si ce rdv ne nous appartient pas
  try {
    const rdv = await apiRequest(`/rdv/${id}`);
    navigation.navigate("Rdv", { rdv });
  } catch (error: any) {
    if (error.message === "SESSION_EXPIRED") {
      navigation.navigate("Login", { redirect: `rdv/${id}` });
    } else if (__DEV__) {
      console.error("[DeepLink] Erreur :", error.message);
    }
  }
}

/**
 * ═══════════════════════════════════════════════════════════════
 * COMPARAISON : APP LINKS / UNIVERSAL LINKS vs SCHÉMA PERSONNALISÉ
 * ═══════════════════════════════════════════════════════════════
 *
 * ┌──────────────────┬─────────────────────────┬─────────────────────────────┐
 * │ Critère          │ Schéma personnalisé     │ App Links / Universal Links │
 * │                  │ (santeplus://)          │ (https://santeplus.ma/...)  │
 * ├──────────────────┼─────────────────────────┼─────────────────────────────┤
 * │ Vérification     │ ❌ AUCUNE               │ ✅ Cryptographique          │
 * │ de propriété     │ N'importe quelle app    │ Fichier JSON signé sur le  │
 * │                  │ peut l'enregistrer      │ domaine HTTPS vérifié      │
 * ├──────────────────┼─────────────────────────┼─────────────────────────────┤
 * │ Android          │ Aucun fichier requis    │ assetlinks.json hébergé à  │
 * │                  │                         │ /.well-known/ contenant le │
 * │                  │                         │ SHA-256 du certificat de   │
 * │                  │                         │ signature de l'APK         │
 * ├──────────────────┼─────────────────────────┼─────────────────────────────┤
 * │ iOS              │ Aucun fichier requis    │ apple-app-site-association │
 * │                  │                         │ contenant le Team ID et le │
 * │                  │                         │ Bundle ID de l'app         │
 * ├──────────────────┼─────────────────────────┼─────────────────────────────┤
 * │ Dialogue de      │ ⚠️ OUI si conflit       │ ❌ NON — ouverture directe │
 * │ choix            │ (plusieurs apps avec    │ dans l'app vérifiée        │
 * │                  │ le même schéma)         │                            │
 * ├──────────────────┼─────────────────────────┼─────────────────────────────┤
 * │ Fallback web     │ ❌ Erreur si l'app      │ ✅ Ouvre le site web si    │
 * │                  │ n'est pas installée     │ l'app n'est pas installée  │
 * ├──────────────────┼─────────────────────────┼─────────────────────────────┤
 * │ Risque principal │ 🔴 LINK HIJACKING       │ 🟢 Impossible sans :       │
 * │                  │ Un malware intercepte   │ 1. Contrôle du domaine     │
 * │                  │ tous les liens          │ 2. Certificat de signature │
 * └──────────────────┴─────────────────────────┴─────────────────────────────┘
 *
 * FICHIER assetlinks.json (Android App Links) :
 * Hébergé à https://santeplus.ma/.well-known/assetlinks.json
 * [{
 *   "relation": ["delegate_permission/common.handle_all_urls"],
 *   "target": {
 *     "namespace": "android_app",
 *     "package_name": "ma.santeplus.app",
 *     "sha256_cert_fingerprints": [
 *       "14:6D:E9:83:C5:73:06:50:D8:EE:B9:95:2F:34:FC:64:..."
 *     ]
 *   }
 * }]
 *
 * FICHIER apple-app-site-association (iOS Universal Links) :
 * Hébergé à https://santeplus.ma/.well-known/apple-app-site-association
 * {
 *   "applinks": {
 *     "apps": [],
 *     "details": [{
 *       "appID": "ABCDE12345.ma.santeplus.app",
 *       "paths": ["/rdv/*", "/article/*"]
 *     }]
 *   }
 * }
 * ═══════════════════════════════════════════════════════════════
 */

