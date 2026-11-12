/**
 * src/screens/OrdonnancesScreen.tsx
 *
 * Écran des ordonnances protégé par authentification biométrique.
 *
 * ═══════════════════════════════════════════════════════════════
 * CONFORMITÉ LOI 09-08 & CNDP (Maroc)
 * ═══════════════════════════════════════════════════════════════
 *
 * Les ordonnances contiennent des prescriptions médicales = données
 * de santé = données sensibles au sens de l'article 1 de la Loi 09-08.
 *
 * L'article 23 impose des "mesures techniques appropriées" pour
 * protéger ces données. La biométrie ajoute une couche de sécurité :
 *
 * Même si :
 * ✅ Le téléphone est déjà déverrouillé (prêté à un tiers)
 * ✅ L'application est ouverte (session active)
 * ❌ Le tiers ne peut PAS voir les ordonnances sans l'empreinte/visage
 *    du propriétaire du téléphone
 *
 * RÉFÉRENCE MASVS : MASVS-AUTH-2
 * "The app uses biometric authentication where appropriate,
 *  with a proper fallback mechanism."
 *
 * ═══════════════════════════════════════════════════════════════
 * FLUX DE L'AUTHENTIFICATION BIOMÉTRIQUE
 * ═══════════════════════════════════════════════════════════════
 *
 *   ┌───────────────────────────┐
 *   │ hasHardwareAsync()        │ ← Le capteur existe-t-il ?
 *   │ Le capteur biométrique    │   (Face ID, empreinte, iris)
 *   │ existe-t-il sur cet      │
 *   │ appareil ?                │
 *   └────────┬─────────────────┘
 *            │
 *       ┌─ OUI ──┐       ┌─ NON ──────────────────────┐
 *       │        │       │ → Fallback : code PIN       │
 *       ▼        │       │   applicatif ou message     │
 *   ┌────────────┴──┐    └────────────────────────────-┘
 *   │ isEnrolledAsync()  │ ← L'utilisateur a-t-il
 *   │ Une empreinte/     │   configuré sa biométrie ?
 *   │ visage est-il      │
 *   │ enregistré ?       │
 *   └────────┬───────────┘
 *            │
 *       ┌─ OUI ──┐       ┌─ NON ──────────────────────┐
 *       │        │       │ → Message : "Configurez     │
 *       ▼        │       │   votre biométrie dans les  │
 *   ┌────────────┴──┐    │   réglages de l'appareil"   │
 *   │ authenticateAsync() └───────────────────────────-┘
 *   │ Prompt biométrique │
 *   │ (Face ID, Touch ID,│
 *   │ empreinte Android) │
 *   └────────┬───────────┘
 *            │
 *       ┌─ SUCCESS ─┐       ┌─ FAIL ─────────────────┐
 *       │           │       │ → "Réessayer" ou        │
 *       ▼           │       │   "Annuler"             │
 *   ┌───────────────┴──┐    └─────────────────────────┘
 *   │ Charger les      │
 *   │ ordonnances      │
 *   │ depuis l'API     │
 *   └──────────────────┘
 * ═══════════════════════════════════════════════════════════════
 */

import React, { useEffect, useState, useCallback } from "react";
import {
  View,
  Text,
  FlatList,
  StyleSheet,
  ActivityIndicator,
  Alert,
  TouchableOpacity,
} from "react-native";
import * as LocalAuthentication from "expo-local-authentication";
import { apiRequest } from "../services/api";

/** Structure d'une ordonnance médicale */
interface Ordonnance {
  id: string;
  date: string;
  medecin: string;
  medicaments: string[];
}

export default function OrdonnancesScreen() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [ordonnances, setOrdonnances] = useState<Ordonnance[]>([]);
  const [loading, setLoading] = useState(true);
  const [biometryLabel, setBiometryLabel] = useState<string>("biométrie");

  // Lancer la vérification biométrique au montage du composant
  useEffect(() => {
    checkBiometricAndAuthenticate();
  }, []);

  /**
   * Vérifie la disponibilité de la biométrie et lance l'authentification.
   *
   * 3 étapes obligatoires (expo-local-authentication) :
   * 1. hasHardwareAsync()  → le capteur physique existe-t-il ?
   * 2. isEnrolledAsync()   → une empreinte/visage est-il enregistré ?
   * 3. authenticateAsync() → demande l'authentification à l'utilisateur
   */
  const checkBiometricAndAuthenticate = useCallback(async () => {
    try {
      // ══════════════════════════════════════════════════════
      // ÉTAPE 1 : Le matériel biométrique est-il disponible ?
      // ══════════════════════════════════════════════════════
      const hasHardware = await LocalAuthentication.hasHardwareAsync();

      if (!hasHardware) {
        // Cas : émulateur, ancien téléphone sans capteur, tablette basique
        Alert.alert(
          "Biométrie non disponible",
          "Votre appareil ne dispose pas de capteur biométrique. " +
            "Pour protéger vos ordonnances médicales, veuillez " +
            "configurer un code PIN de sécurité dans les paramètres " +
            "de l'application.\n\n" +
            "Cette protection est requise par la Loi 09-08 pour les " +
            "données de santé.",
          [{ text: "Compris", onPress: () => handleFallbackAuth() }]
        );
        return;
      }

      // ══════════════════════════════════════════════════════
      // ÉTAPE 2 : L'utilisateur a-t-il configuré la biométrie ?
      // ══════════════════════════════════════════════════════
      const isEnrolled = await LocalAuthentication.isEnrolledAsync();

      if (!isEnrolled) {
        // Le capteur existe mais aucune empreinte/visage n'est enregistré
        Alert.alert(
          "Biométrie non configurée",
          "Veuillez configurer Face ID ou votre empreinte digitale " +
            "dans les Réglages de votre appareil pour accéder à vos " +
            "ordonnances.\n\n" +
            "Cette vérification protège vos données de santé " +
            "(conformément à la Loi 09-08, art. 23).",
          [{ text: "Compris", onPress: () => handleFallbackAuth() }]
        );
        return;
      }

      // ── Détection du type de biométrie pour l'affichage ─────
      const types =
        await LocalAuthentication.supportedAuthenticationTypesAsync();

      if (
        types.includes(
          LocalAuthentication.AuthenticationType.FACIAL_RECOGNITION
        )
      ) {
        setBiometryLabel("Face ID");
      } else if (
        types.includes(LocalAuthentication.AuthenticationType.FINGERPRINT)
      ) {
        setBiometryLabel("empreinte digitale");
      } else if (
        types.includes(
          LocalAuthentication.AuthenticationType.IRIS
        )
      ) {
        setBiometryLabel("iris");
      }

      // ══════════════════════════════════════════════════════
      // ÉTAPE 3 : Demande d'authentification biométrique
      // ══════════════════════════════════════════════════════
      const result = await LocalAuthentication.authenticateAsync({
        promptMessage:
          "Vérifiez votre identité pour accéder aux ordonnances",
        cancelLabel: "Annuler",
        // disableDeviceFallback: false
        // → Si la biométrie échoue 3 fois, le code PIN/mot de passe
        //   de l'APPAREIL est proposé comme fallback
        // → C'est une bonne pratique UX recommandée par Apple et Google
        disableDeviceFallback: false,
        fallbackLabel: "Utiliser le code de l'appareil",
      });

      if (result.success) {
        // ✅ Authentification réussie → charger les ordonnances
        setIsAuthenticated(true);
        await loadOrdonnances();
      } else {
        // L'utilisateur a annulé ou la biométrie a échoué
        Alert.alert(
          "Authentification requise",
          "Vous devez vous authentifier pour consulter vos ordonnances.",
          [
            {
              text: "Réessayer",
              onPress: () => checkBiometricAndAuthenticate(),
            },
            { text: "Annuler" },
          ]
        );
      }
    } catch (error) {
      if (__DEV__) {
        console.error("[Biométrie] Erreur :", error);
      }
      handleFallbackAuth();
    } finally {
      setLoading(false);
    }
  }, []);

  /**
   * Fallback quand la biométrie n'est pas disponible ou non configurée.
   *
   * En production, on implémenterait :
   * - Un code PIN applicatif (4-6 chiffres) stocké de manière sécurisée
   * - Ou une re-saisie du mot de passe de connexion
   * - Avec verrouillage après 3 tentatives échouées
   */
  const handleFallbackAuth = useCallback(() => {
    Alert.alert(
      "Authentification alternative",
      "La biométrie n'est pas disponible sur cet appareil. " +
        "En production, un code PIN applicatif serait demandé ici " +
        "pour protéger l'accès aux ordonnances.",
      [{ text: "OK" }]
    );
    setLoading(false);
  }, []);

  /** Charge les ordonnances depuis l'API sécurisée (avec Bearer token). */
  const loadOrdonnances = useCallback(async () => {
    try {
      // apiRequest() ajoute automatiquement Authorization: Bearer <token>
      // Le backend filtre les ordonnances par userId du JWT
      const data = await apiRequest<Ordonnance[]>("/ordonnances");
      setOrdonnances(data);
    } catch (error: any) {
      Alert.alert(
        "Erreur",
        "Impossible de charger les ordonnances. " +
          "Vérifiez votre connexion Internet."
      );
    }
  }, []);

  // ── ÉTAT : Chargement / Vérification biométrique ──────────
  if (loading) {
    return (
      <View style={styles.centerContainer}>
        <ActivityIndicator size="large" color="#2E86AB" />
        <Text style={styles.loadingText}>
          Vérification biométrique en cours…
        </Text>
      </View>
    );
  }

  // ── ÉTAT : Non authentifié (biométrie échouée ou annulée) ──
  if (!isAuthenticated) {
    return (
      <View style={styles.centerContainer}>
        <Text style={styles.lockIcon}>🔒</Text>
        <Text style={styles.lockedTitle}>Accès protégé</Text>
        <Text style={styles.lockedText}>
          L'authentification biométrique est requise pour consulter
          vos ordonnances médicales.{"\n\n"}
          Vos données de santé sont protégées conformément à la
          Loi 09-08 relative à la protection des données à
          caractère personnel.
        </Text>
        <TouchableOpacity
          style={styles.retryButton}
          onPress={checkBiometricAndAuthenticate}
          accessibilityLabel={`S'authentifier avec ${biometryLabel}`}
        >
          <Text style={styles.retryButtonText}>
            S'authentifier avec {biometryLabel}
          </Text>
        </TouchableOpacity>
      </View>
    );
  }

  // ── ÉTAT : Authentifié → Affichage des ordonnances ─────────
  return (
    <View style={styles.container}>
      <Text style={styles.title}>📋 Mes ordonnances</Text>
      <FlatList
        data={ordonnances}
        keyExtractor={(item) => item.id}
        renderItem={({ item }) => (
          <View style={styles.card}>
            <Text style={styles.cardTitle}>Dr. {item.medecin}</Text>
            <Text style={styles.cardDate}>📅 {item.date}</Text>
            {item.medicaments.map((med, index) => (
              <Text key={index} style={styles.medicament}>
                💊 {med}
              </Text>
            ))}
          </View>
        )}
        ListEmptyComponent={
          <Text style={styles.emptyText}>
            Aucune ordonnance trouvée.
          </Text>
        }
      />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    padding: 16,
    backgroundColor: "#F5F7FA",
  },
  centerContainer: {
    flex: 1,
    justifyContent: "center",
    alignItems: "center",
    padding: 32,
    backgroundColor: "#F5F7FA",
  },
  title: {
    fontSize: 24,
    fontWeight: "bold",
    marginBottom: 16,
    color: "#1A1A2E",
  },
  loadingText: {
    marginTop: 12,
    fontSize: 14,
    color: "#666",
  },
  lockIcon: {
    fontSize: 64,
    marginBottom: 16,
  },
  lockedTitle: {
    fontSize: 22,
    fontWeight: "bold",
    marginBottom: 12,
    color: "#1A1A2E",
  },
  lockedText: {
    fontSize: 14,
    color: "#555",
    textAlign: "center",
    marginBottom: 28,
    lineHeight: 22,
  },
  retryButton: {
    backgroundColor: "#2E86AB",
    paddingHorizontal: 28,
    paddingVertical: 14,
    borderRadius: 10,
    shadowColor: "#2E86AB",
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.3,
    shadowRadius: 6,
    elevation: 4,
  },
  retryButtonText: {
    color: "#FFF",
    fontSize: 16,
    fontWeight: "600",
  },
  card: {
    backgroundColor: "#FFF",
    padding: 16,
    borderRadius: 10,
    marginBottom: 12,
    shadowColor: "#000",
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.08,
    shadowRadius: 4,
    elevation: 2,
  },
  cardTitle: {
    fontSize: 16,
    fontWeight: "600",
    color: "#1A1A2E",
  },
  cardDate: {
    fontSize: 13,
    color: "#888",
    marginTop: 4,
    marginBottom: 10,
  },
  medicament: {
    fontSize: 14,
    color: "#333",
    marginLeft: 4,
    marginTop: 2,
    lineHeight: 20,
  },
  emptyText: {
    textAlign: "center",
    color: "#999",
    marginTop: 40,
    fontSize: 15,
  },
});

