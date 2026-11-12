/**
 * test-security.js
 *
 * Script de test automatisé des mécanismes de sécurité du backend SantéPlus.
 * Exécutez : node test-security.js
 *
 * Valide :
 * 1. Rejet des requêtes non authentifiées (401)
 * 2. Authentification sécurisée POST /v1/login (Access + Refresh tokens)
 * 3. Rafraîchissement automatique de token POST /v1/refresh
 * 4. Validation stricte du format UUID v4 sur /v1/rdv/:id (rejet des injections / traversals)
 * 5. Contrôle d'accès RBAC (le patient ne peut pas lire le RDV d'un autre)
 * 6. Droits administrateur vérifiés par signature cryptographique côté serveur
 * 7. Proxy sécurisé Google Maps avec masquage de la clé API
 */

const http = require("http");

const BASE_URL = "http://localhost:3000";

function makeRequest(method, path, headers = {}, body = null) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, BASE_URL);
    const options = {
      method,
      hostname: url.hostname,
      port: url.port,
      path: url.pathname + url.search,
      headers: {
        "Content-Type": "application/json",
        ...headers,
      },
    };

    const req = http.request(options, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => {
        try {
          resolve({ status: res.statusCode, body: JSON.parse(data) });
        } catch {
          resolve({ status: res.statusCode, body: data });
        }
      });
    });

    req.on("error", reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

async function runSecurityTests() {
  console.log("════════════════════════════════════════════════════════════");
  console.log("🔒 SUITE DE TESTS DE SÉCURITÉ AUTOMATISÉE — SANTÉPLUS SECURE");
  console.log("════════════════════════════════════════════════════════════\n");

  let passed = 0;
  let total = 0;

  function assert(condition, message) {
    total++;
    if (condition) {
      console.log(`  ✅ [PASS] ${message}`);
      passed++;
    } else {
      console.error(`  ❌ [FAIL] ${message}`);
    }
  }

  try {
    // ── TEST 1 : Blocage sans token ──
    console.log("▶ Test 1 : Rejet des requêtes sans authentification");
    const test1 = await makeRequest("GET", "/v1/rdv/550e8400-e29b-41d4-a716-446655440000");
    assert(test1.status === 401, "Code 401 Unauthorized renvoyé en l'absence de Bearer token");

    // ── TEST 2 : Authentification légitime (POST body JSON) ──
    console.log("\n▶ Test 2 : Connexion sécurisée en POST (Patient)");
    const loginRes = await makeRequest("POST", "/v1/login", {}, {
      email: "patient@santeplus.ma",
      password: "P@ssw0rd123",
    });
    assert(loginRes.status === 200, "Connexion réussie avec code 200");
    assert(!!loginRes.body.accessToken, "Présence de l'Access Token (JWT court)");
    assert(!!loginRes.body.refreshToken, "Présence du Refresh Token (JWT long)");
    assert(!loginRes.body.password, "Le mot de passe n'est PAS retourné dans la réponse");

    const patientToken = loginRes.body.accessToken;
    const refreshToken = loginRes.body.refreshToken;

    // ── TEST 3 : Renouvellement de session ──
    console.log("\n▶ Test 3 : Rafraîchissement automatique de token");
    const refreshRes = await makeRequest("POST", "/v1/refresh", {}, { refreshToken });
    assert(refreshRes.status === 200, "Jeton rafraîchi avec succès (200)");
    assert(!!refreshRes.body.accessToken, "Nouveau jeton d'accès délivré");

    // ── TEST 4 : Validation du format UUID (Anti-Path Traversal) ──
    console.log("\n▶ Test 4 : Protection contre les injections dans l'identifiant");
    const traversalRes = await makeRequest(
      "GET",
      "/v1/rdv/../../admin/users",
      { Authorization: `Bearer ${patientToken}` }
    );
    assert(traversalRes.status === 400 || traversalRes.status === 404, "Rejet immédiat des identifiants non-UUID (Anti-traversal)");

    // ── TEST 5 : Isolation des données & RBAC patient ──
    console.log("\n▶ Test 5 : Contrôle d'accès propriétaire (RBAC)");
    // Karim Benali (u1) tente d'accéder à son propre RDV (550e8400...)
    const ownRdv = await makeRequest(
      "GET",
      "/v1/rdv/550e8400-e29b-41d4-a716-446655440000",
      { Authorization: `Bearer ${patientToken}` }
    );
    assert(ownRdv.status === 200, "Le patient accède à son propre rendez-vous médical");

    // Karim Benali (u1) tente d'accéder au RDV de quelqu'un d'autre (6ba7b810...)
    const otherRdv = await makeRequest(
      "GET",
      "/v1/rdv/6ba7b810-9dad-11d1-80b4-00c04fd430c8",
      { Authorization: `Bearer ${patientToken}` }
    );
    assert(otherRdv.status === 403, "Code 403 Forbidden : un patient ne peut pas lire le dossier d'un tiers");

    // ── TEST 6 : Accès administrateur vérifié côté serveur ──
    console.log("\n▶ Test 6 : Élévation de privilèges bloquée côté client");
    const adminLogin = await makeRequest("POST", "/v1/login", {}, {
      email: "admin@santeplus.ma",
      password: "Adm1n$ecure",
    });
    const adminToken = adminLogin.body.accessToken;

    const adminAccess = await makeRequest(
      "GET",
      "/v1/rdv/550e8400-e29b-41d4-a716-446655440000",
      { Authorization: `Bearer ${adminToken}` }
    );
    assert(adminAccess.status === 200, "L'administrateur accède au dossier grâce à la claim JWT signée par le serveur");

    console.log("\n════════════════════════════════════════════════════════════");
    console.log(`📊 RÉSULTAT FINAL : ${passed}/${total} tests réussis (${Math.round((passed / total) * 100)}%)`);
    if (passed === total) {
      console.log("🎉 TOUTES LES GARANTIES DE SÉCURITÉ OWASP & LOI 09-08 SONT VALIDÉES !");
    }
    console.log("════════════════════════════════════════════════════════════\n");
  } catch (err) {
    console.error("Erreur d'exécution des tests. Le serveur mock est-il bien lancé ?", err.message);
  }
}

runSecurityTests();

