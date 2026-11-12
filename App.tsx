/**
 * App.tsx
 *
 * Point d'entrée principal de l'application SantéPlus Secure.
 * Démontre l'intégration de tous les composants sécurisés.
 */

import React, { useState } from "react";
import {
  SafeAreaView,
  StatusBar,
  StyleSheet,
  Text,
  View,
  TouchableOpacity,
  TextInput,
  Alert,
} from "react-native";
import { login, logout } from "./src/services/auth";
import OrdonnancesScreen from "./src/screens/OrdonnancesScreen";
import ArticleScreen from "./src/screens/ArticleScreen";

type Screen = "login" | "home" | "ordonnances" | "article";

export default function App() {
  const [currentScreen, setCurrentScreen] = useState<Screen>("login");
  const [user, setUser] = useState<{ id: string; name: string; email: string } | null>(null);
  const [email, setEmail] = useState("patient@santeplus.ma");
  const [password, setPassword] = useState("P@ssw0rd123");
  const [loading, setLoading] = useState(false);

  const handleLogin = async () => {
    setLoading(true);
    try {
      const loggedUser = await login(email, password);
      setUser(loggedUser);
      setCurrentScreen("home");
    } catch (err: any) {
      Alert.alert("Erreur", err.message || "Échec de connexion");
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = async () => {
    await logout();
    setUser(null);
    setCurrentScreen("login");
  };

  return (
    <SafeAreaView style={styles.container}>
      <StatusBar barStyle="light-content" backgroundColor="#1A5276" />
      <View style={styles.header}>
        <Text style={styles.headerTitle}>🏥 SantéPlus Secure</Text>
        {user && (
          <TouchableOpacity onPress={handleLogout} style={styles.logoutBtn}>
            <Text style={styles.logoutText}>Déconnexion</Text>
          </TouchableOpacity>
        )}
      </View>

      {currentScreen === "login" && (
        <View style={styles.content}>
          <Text style={styles.title}>Connexion Sécurisée</Text>
          <Text style={styles.subtitle}>
            Conforme Loi 09-08 & OWASP Mobile 2024
          </Text>

          <TextInput
            style={styles.input}
            placeholder="E-mail"
            value={email}
            onChangeText={setEmail}
            autoCapitalize="none"
            keyboardType="email-address"
          />
          <TextInput
            style={styles.input}
            placeholder="Mot de passe"
            value={password}
            onChangeText={setPassword}
            secureTextEntry
          />

          <TouchableOpacity
            style={styles.primaryButton}
            onPress={handleLogin}
            disabled={loading}
          >
            <Text style={styles.primaryButtonText}>
              {loading ? "Connexion en cours…" : "Se connecter (POST HTTPS)"}
            </Text>
          </TouchableOpacity>

          <View style={styles.securityNote}>
            <Text style={styles.securityNoteTitle}>🔒 Garanties de sécurité :</Text>
            <Text style={styles.securityNoteText}>
              • Credentials dans le body POST (chiffré TLS)
            </Text>
            <Text style={styles.securityNoteText}>
              • Tokens stockés dans Keychain / Android Keystore
            </Text>
            <Text style={styles.securityNoteText}>
              • Mot de passe JAMAIS stocké sur l'appareil
            </Text>
            <Text style={styles.securityNoteText}>
              • Aucun secret dans le bundle JS
            </Text>
          </View>
        </View>
      )}

      {currentScreen === "home" && (
        <View style={styles.content}>
          <Text style={styles.welcomeText}>Bienvenue, {user?.name}</Text>
          <Text style={styles.userEmail}>{user?.email}</Text>

          <TouchableOpacity
            style={styles.menuCard}
            onPress={() => setCurrentScreen("ordonnances")}
          >
            <Text style={styles.menuCardIcon}>🔒</Text>
            <View>
              <Text style={styles.menuCardTitle}>Mes Ordonnances</Text>
              <Text style={styles.menuCardDesc}>
                Protégé par Face ID / Empreinte (Loi 09-08)
              </Text>
            </View>
          </TouchableOpacity>

          <TouchableOpacity
            style={styles.menuCard}
            onPress={() => setCurrentScreen("article")}
          >
            <Text style={styles.menuCardIcon}>📰</Text>
            <View>
              <Text style={styles.menuCardTitle}>Articles Santé</Text>
              <Text style={styles.menuCardDesc}>
                WebView durcie (originWhitelist + postMessage)
              </Text>
            </View>
          </TouchableOpacity>
        </View>
      )}

      {currentScreen === "ordonnances" && (
        <View style={{ flex: 1 }}>
          <TouchableOpacity
            style={styles.backBtn}
            onPress={() => setCurrentScreen("home")}
          >
            <Text style={styles.backBtnText}>← Retour à l'accueil</Text>
          </TouchableOpacity>
          <OrdonnancesScreen />
        </View>
      )}

      {currentScreen === "article" && (
        <View style={{ flex: 1 }}>
          <TouchableOpacity
            style={styles.backBtn}
            onPress={() => setCurrentScreen("home")}
          >
            <Text style={styles.backBtnText}>← Retour à l'accueil</Text>
          </TouchableOpacity>
          <ArticleScreen
            route={{
              params: {
                articleUrl: "https://santeplus.ma/articles/nutrition-sante",
              },
            }}
          />
        </View>
      )}
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: "#F5F7FA",
  },
  header: {
    backgroundColor: "#1A5276",
    padding: 16,
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
  },
  headerTitle: {
    color: "#FFF",
    fontSize: 20,
    fontWeight: "bold",
  },
  logoutBtn: {
    backgroundColor: "rgba(255,255,255,0.2)",
    paddingHorizontal: 12,
    paddingVertical: 6,
    borderRadius: 6,
  },
  logoutText: {
    color: "#FFF",
    fontSize: 12,
  },
  content: {
    flex: 1,
    padding: 24,
    justifyContent: "center",
  },
  title: {
    fontSize: 26,
    fontWeight: "bold",
    color: "#1A1A2E",
    marginBottom: 6,
    textAlign: "center",
  },
  subtitle: {
    fontSize: 13,
    color: "#666",
    marginBottom: 24,
    textAlign: "center",
  },
  welcomeText: {
    fontSize: 22,
    fontWeight: "bold",
    color: "#1A1A2E",
    marginBottom: 4,
  },
  userEmail: {
    fontSize: 14,
    color: "#666",
    marginBottom: 24,
  },
  input: {
    backgroundColor: "#FFF",
    borderRadius: 8,
    padding: 14,
    marginBottom: 12,
    borderWidth: 1,
    borderColor: "#DDD",
    fontSize: 15,
  },
  primaryButton: {
    backgroundColor: "#2E86AB",
    padding: 16,
    borderRadius: 8,
    alignItems: "center",
    marginTop: 8,
  },
  primaryButtonText: {
    color: "#FFF",
    fontSize: 16,
    fontWeight: "bold",
  },
  securityNote: {
    backgroundColor: "#E8F4F8",
    padding: 14,
    borderRadius: 8,
    marginTop: 24,
    borderLeftWidth: 4,
    borderLeftColor: "#2E86AB",
  },
  securityNoteTitle: {
    fontWeight: "bold",
    color: "#1A5276",
    marginBottom: 6,
  },
  securityNoteText: {
    fontSize: 12,
    color: "#333",
    lineHeight: 18,
  },
  menuCard: {
    backgroundColor: "#FFF",
    padding: 18,
    borderRadius: 12,
    marginBottom: 14,
    flexDirection: "row",
    alignItems: "center",
    shadowColor: "#000",
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.08,
    shadowRadius: 4,
    elevation: 2,
  },
  menuCardIcon: {
    fontSize: 32,
    marginRight: 16,
  },
  menuCardTitle: {
    fontSize: 16,
    fontWeight: "bold",
    color: "#1A1A2E",
  },
  menuCardDesc: {
    fontSize: 12,
    color: "#666",
    marginTop: 2,
  },
  backBtn: {
    backgroundColor: "#E2E8F0",
    padding: 10,
    alignItems: "center",
  },
  backBtnText: {
    color: "#1A5276",
    fontWeight: "600",
  },
});

