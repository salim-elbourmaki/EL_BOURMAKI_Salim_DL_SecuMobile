# SantePlus Secure - Application Mobile Medicale Durcie

[![OWASP Mobile Top 10](https://img.shields.io/badge/OWASP-Mobile_Top_10_2024-red.svg)](https://owasp.org/www-project-mobile-top-10/)
[![OWASP MASVS](https://img.shields.io/badge/OWASP-MASVS_v2.0-blue.svg)](https://mas.owasp.org/MASVS/)
[![Conformite CNDP](https://img.shields.io/badge/Conformite-Loi_09--08_CNDP-darkblue.svg)](https://www.cndp.ma/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.3-blue.svg?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![React Native](https://img.shields.io/badge/React_Native-0.76-61DAFB.svg?logo=react&logoColor=black)](https://reactnative.dev/)
[![Expo SDK 52](https://img.shields.io/badge/Expo-SDK_52-black.svg?logo=expo&logoColor=white)](https://docs.expo.dev/)
[![Node.js](https://img.shields.io/badge/Node.js-18+-green.svg?logo=node.js&logoColor=white)](https://nodejs.org/)

Application mobile React Native / Expo de prise de rendez-vous medicaux et de consultation d'ordonnances, auditee et durcie selon les recommandations OWASP Mobile Top 10 (2024), le standard OWASP MASVS v2.0, et les exigences reglementaires marocaines definies par la Loi 09-08 sous le controle de la CNDP.

---

## Informations Academiques et Cadre du Projet

* **Projet :** Audit de Securite et Durcissement d'une Application Mobile Medicale (SantePlus)
* **Formation :** Master Systemes Intelligents et Cybersecurite (SIC)
* **Etablissement :** Faculte des Sciences et Techniques de Tanger (FSTT), Universite Abdelmalek Essaadi
* **Etudiant :** EL BOURMAKI Salim
* **Encadrant :** Pr. ZILI Hassan
* **Document de reference :** `EL_BOURMAKI_Salim_DL_SecuMobile.pdf`

---

## Table des Matieres

- [Presentation et Objectifs de Securite](#presentation-et-objectifs-de-securite)
- [Stack Technique et Technologies Utilisees](#stack-technique-et-technologies-utilisees)
- [Matrice de Durcissement (Mapping OWASP et Fichiers)](#matrice-de-durcissement-mapping-owasp-et-fichiers)
- [Arborescence du Depot](#arborescence-du-depot)
- [Guide d'Installation et d'Execution](#guide-dinstallation-et-dexecution)
- [Guide de Validation et de Demonstration des Mecanismes de Securite](#guide-de-validation-et-de-demonstration-des-mecanismes-de-securite)
- [Conformite Reglementaire : Loi Marocaine 09-08 et CNDP](#conformite-reglementaire--loi-marocaine-09-08-et-cndp)

---

## Presentation et Objectifs de Securite

L'application SantePlus traite des donnees a caractere personnel hautement sensibles relatives a la sante des patients (dossiers medicaux, rendez-vous, ordonnances et prescriptions). L'analyse de securite initiale a revele 14 vulnerabilites critiques couvrant l'exposition de secrets en clair, des communications non chiffrees, des faiblesses d'autorisation et d'authentification, ainsi que des risques d'execution de code arbitraire.

Ce depot presente le code source integralement refondu et durci selon trois piliers directeurs :

1. **Defense en Profondeur (Defense in Depth) :** Combinaison de protections au niveau du systeme d'exploitation mobile (Keystore/Keychain), de la couche applicative (validation stricte des entrees, pont WebView sandboxe) et de la couche reseau/backend (TLS 1.3 forcant, RBAC, jetons ephemeres).
2. **Moindre Privilege (Principle of Least Privilege) :** Restriction des permissions Android manifestes, elimination de l'exposition globale de cles API tierces, et cloisonnement strict des acces aux seules ressources appartenant a l'utilisateur authentifie.
3. **Refus de Confiance envers le Terminal (Never Trust the Client) :** Deplacement integral des verifications d'autorisation (RBAC) sur le serveur distant et signature cryptographique HMAC-SHA256 non falsifiable des claims utilisateur via JSON Web Tokens.

---

## Stack Technique et Technologies Utilisees

| Domaine | Technologie / Outil | Version | Role et Implementation Technique |
|---|---|---|---|
| **Frontend Mobile** | React Native | 0.76.0 | Framework mobile multiplateforme executant l'interface utilisateur durcie. |
| **Frontend Mobile** | TypeScript | 5.3.3 | Typage statique strict prevenant les injections et erreurs de manipulation de donnees. |
| **Frontend Mobile** | Expo SDK | 52.0.0 | Plateforme applicative mobile fournissant l'environnement d'execution securise. |
| **Frontend Mobile** | Expo Go | 52.x | Environnement de test et d'execution directe sur terminal physique ou emulateur. |
| **Frontend Mobile** | React Navigation | 6.x | Gestionnaire de navigation et resolution controlee des routes de Deep Linking. |
| **Securite Mobile** | `expo-secure-store` | 14.0.0 | Stockage chiffre materiel (Android Keystore / iOS Keychain) avec `WHEN_UNLOCKED_THIS_DEVICE_ONLY`. |
| **Securite Mobile** | `expo-local-authentication` | 15.0.0 | Authentification biométrique native (Face ID / Empreinte digitale) protegeant l'acces aux ordonnances. |
| **Securite Mobile** | `react-native-webview` | 13.12.2 | Composant de navigation web embarque, isole par liste blanche d'origines et pont sans `eval()`. |
| **Backend & API** | Node.js | 18+ | Moteur d'execution JavaScript cote serveur pour l'API REST de demonstration. |
| **Backend & API** | Express.js | 4.21.1 | Framework serveur gerant le routage, les middlewares de securite et le parsing JSON. |
| **Backend & API** | `jsonwebtoken` | 9.0.2 | Generation et verification cryptographique des jetons JWT (Access Token 15m, Refresh Token 7j). |
| **Backend & API** | CORS & Middlewares | 2.8.5 | Cloisonnement des origines clientes et verification d'en-tetes HTTP. |
| **Audit & Tests** | Scripts de test natifs | ES6 / Node | Suite d'evaluation automatique des mecanismes de protection (`test-security.js`). |
| **Audit & Tests** | PoC d'attaque offensif | ES6 / Node | Demonstration live de l'echec des vecteurs d'attaque courants (`demo-exploits.js`). |
| **Audit & Tests** | Expo URI Scheme CLI | 1.3.x | Outil de test en ligne de commande pour la simulation de Deep Links intrusifs. |
| **Versionnement** | Git | 2.x | Suivi de versions avec historique atomique conventionnel (feat, fix, refactor, sec). |

---

## Matrice de Durcissement (Mapping OWASP et Fichiers)

Le tableau suivant resume les 14 vulnerabilites identifiees lors de l'audit initial, leur classification selon le referentiel OWASP Mobile Top 10 (2024), la solution technique appliquee et les fichiers sources concernes.

| # | Vulnerabilite Initiale | Categorie OWASP 2024 | Solution Technique Appliquee | Fichier(s) Source(s) Durci(s) |
|---|---|---|---|---|
| 1 | Communication en texte clair (`http://api.santeplus.ma/v1`) | **M5 : Insecure Communication** | Forcage systematique de HTTPS (TLS 1.3) et desactivation des flux non chiffres. | `src/config.ts` |
| 2 | Cle secrete Google Maps encodee en dur dans le code client | **M1 : Improper Credential Usage** | Deplacement de la cle dans le backend (`.env`) et creation d'un proxy `/v1/maps/geocode`. | `src/config.ts`, `server/server.js`, `src/services/api.ts` |
| 3 | Activation permanente des logs de debogage (`DEBUG = true`) | **M8 : Security Misconfiguration** | Remplacement par la directive native `__DEV__` (automatiquement desactivee en production). | `src/config.ts`, `src/services/auth.ts` |
| 4 | Identifiants transmis en clair dans l'URL (GET query params) | **M5 : Insecure Communication** | Remplacement par une requete HTTP POST avec corps JSON chiffre en transit via TLS. | `src/services/auth.ts`, `server/server.js` |
| 5 | Journalisation systeme de jetons et de donnees personnelles | **M9 : Insecure Data Storage** | Assainissement des journaux console et suppression absolue de tout log de secret. | `src/services/auth.ts` |
| 6 | Stockage du jeton d'authentification en clair dans `AsyncStorage` | **M9 : Insecure Data Storage** | Migration vers `expo-secure-store` adosse au Keystore materiel / Keychain iOS. | `src/services/secureStorage.ts` |
| 7 | Persistance du mot de passe utilisateur en clair sur le disque | **M9 : Insecure Data Storage** | Suppression definitive de la persistance du mot de passe ; rotation Access/Refresh tokens. | `src/services/secureStorage.ts`, `src/services/auth.ts` |
| 8 | Controle des privileges `isAdmin()` effectue cote client | **M3 : Insecure Authorization** | Controle d'acces RBAC et verification de propriete effectues exclusivement cote serveur via JWT. | `server/server.js`, `src/services/api.ts` |
| 9 | Parametre d'identifiant `id` non filtre dans les Deep Links | **M4 : Insufficient Validation** | Validation stricte par expression reguliere RFC 4122 (UUID v4) avant toute requete API. | `src/navigation/linking.ts` |
| 10 | Jeton d'authentification expose dans l'URL du Deep Link | **M1 : Improper Credential Usage** | Injection du jeton exclusivement par l'en-tete standard `Authorization: Bearer` (RFC 6750). | `src/navigation/linking.ts`, `src/services/api.ts` |
| 11 | Schema d'URL personnalise sans verification de session active | **M3 : Insecure Authentication** | Verification prealable de l'etat de session et configuration Android App Links (`autoVerify`). | `src/navigation/linking.ts`, `app.json` |
| 12 | Liste blanche de la WebView ouverte a l'ensemble du web (`*`) | **M8 : Security Misconfiguration** | Restriction stricte du composant au domaine officiel `https://santeplus.ma` via liste blanche. | `src/screens/ArticleScreen.tsx` |
| 13 | Execution arbitraire de code via `eval()` dans le pont WebView | **M4 : Insufficient Validation** | Binarisation et typage du pont de messages avec liste blanche d'actions (`ALLOWED_ACTIONS`). | `src/screens/ArticleScreen.tsx` |
| 14 | Configuration permissive du fichier AndroidManifest | **M8 / M5 / M9** | Durcissement `app.json` : `usesCleartextTraffic=false`, `allowBackup=false`, `debuggable=false`. | `app.json` |
| B1 | Consultation libre des ordonnances sans authentification forte | **Loi 09-08 (Art. 23) / MASVS-AUTH** | Verrouillage de l'acces aux donnees de sante par challenge biometrique (`expo-local-authentication`). | `src/screens/OrdonnancesScreen.tsx` |

---

## Arborescence du Depot

L'arborescence du projet est structuree de maniere plate a la racine du depot Git, sans sous-dossier intermediaire :

```text
.
├── .env.example                     # Modele des variables d'environnement publiques client
├── .gitignore                       # Exclusion des modules node, artefacts de build et fichiers .env
├── app.json                         # Configuration Expo durcie (permissions, App Links, flags de build)
├── App.tsx                          # Point d'entree applicatif et orchestration de la navigation
├── package.json                     # Declarations des dependances et scripts applicatifs React Native
├── package-lock.json                # Verrouillage exact des versions du runtime mobile
├── tsconfig.json                    # Configuration TypeScript autonome avec options de verification stricte
├── README.md                        # Documentation technique d'audit et guide d'exploitation du projet
├── EL_BOURMAKI_Salim_DL_SecuMobile.pdf # Rapport academique complet d'audit et de durcissement (PDF final)
├── assets/                          # Ressources visuelles applicatives
│   ├── adaptive-icon.png            # Icone adaptive pour terminaux Android
│   ├── favicon.png                  # Favicon web
│   ├── icon.png                     # Icone standard de l'application SantePlus
│   └── splash-icon.png              # Ecran de chargement initial (Splash Screen)
├── server/                          # Mock Backend REST Express securise
│   ├── .env.example                 # Variables d'environnement privees du serveur (secrets JWT et Maps)
│   ├── package.json                 # Dependances et scripts du serveur Node.js
│   ├── package-lock.json            # Verrouillage des dependances du serveur
│   ├── server.js                    # Serveur Express : authentification JWT, RBAC, proxy Google Maps
│   ├── test-security.js             # Suite de tests automatisee validant les 7 invariants de securite
│   └── demo-exploits.js             # Script de demonstration des vecteurs d'attaque neutralises
└── src/                             # Code source TypeScript durci de l'application mobile
    ├── config.ts                    # Constantes de configuration securisees (HTTPS obligatoire, __DEV__)
    ├── navigation/
    │   └── linking.ts               # Configuration du Deep Linking avec validation UUID v4 et guard
    ├── screens/
    │   ├── ArticleScreen.tsx        # WebView medicale securisee avec filtrage de navigation et anti-eval
    │   └── OrdonnancesScreen.tsx    # Consultation d'ordonnances protegee par defi biometrique
    └── services/
        ├── api.ts                   # Client HTTP centralise (injection Bearer RFC 6750 et auto-refresh)
        ├── auth.ts                  # Service d'authentification POST sans persistance de mot de passe
        └── secureStorage.ts         # Abstraction du stockage chiffre materiel via expo-secure-store
```

---

## Guide d'Installation et d'Execution

### 1. Prerequis Systeme

* **Node.js :** Version 18.x ou superieure installee sur le poste de developpement.
* **npm :** Gestionnaire de paquets livre avec Node.js.
* **Terminal de test :** Smartphone physique avec l'application **Expo Go** installee (disponible sur Google Play Store et Apple App Store), ou un emulateur Android Studio / simulateur iOS Xcode operationnel.

### 2. Configuration des Environnements

Initialisez les fichiers d'environnement a partir des gabarits fournis :

```bash
# Configuration client (racine du projet)
cp .env.example .env

# Configuration serveur
cp server/.env.example server/.env
```

Contenu recommande pour `server/.env` :
```env
PORT=3000
JWT_SECRET=super-secret-key-32-chars-minimum-santeplus-2026!
MAPS_API_KEY=AIzaSyD-santeplus-cle-prod-4f9a2b
```

### 3. Installation des Dependances

Installez les dependances du client mobile ainsi que celles du backend simule :

```bash
# Dependances de l'application React Native (a la racine)
npm install

# Dependances du mock backend
cd server
npm install
cd ..
```

### 4. Demarrage du Backend Securise

Dans un premier terminal, demarrez le serveur Express simulant l'API securisee de SantePlus :

```bash
npm run server
```

Sortie console attendue :
```text
SantePlus Mock API demarree sur http://localhost:3000
Routes securisees actives :
   POST /v1/login        - Authentification avec generation de tokens
   POST /v1/refresh      - Renouvellement du jeton d'acces
   GET  /v1/rdv/:id      - Consultation de RDV avec verification RBAC
   GET  /v1/ordonnances  - Consultation des ordonnances (isolee par patient)
   GET  /v1/maps/geocode - Proxy securise Google Maps
```

### 5. Lancement de l'Application Mobile

Dans un second terminal (a la racine du projet), lancez le serveur de developpement Expo :

```bash
npm start
```

* **Test sur terminal physique :** Assurez-vous que votre telephone et votre ordinateur sont connectes au meme reseau local (Wi-Fi). Dans le fichier `.env` a la racine, configurez l'adresse IP locale de votre machine (ex: `API_URL=http://192.168.1.50:3000/v1`). Scannez ensuite le QR code affiche dans le terminal avec l'application **Expo Go**.
* **Test sur emulateur :** Pressez la touche `a` pour lancer l'emulateur Android, ou la touche `i` pour le simulateur iOS.

---

## Guide de Validation et de Demonstration des Mecanismes de Securite

### Comptes de Test Preconfigures

| Role | Identifiant (Email) | Mot de passe | Privileges et Cloisonnement |
|---|---|---|---|
| **Patient** | `patient@santeplus.ma` | `P@ssw0rd123` | Acces limite strictement a son profil, ses ordonnances et son RDV (`550e8400...`). Rejet systematique sur les ressources d'autrui. |
| **Medecin / Administrateur** | `admin@santeplus.ma` | `Adm1n$ecure` | Privileges etendus : consultation des dossiers de l'ensemble des patients. |

---

### Scenario A : Execution de la Suite de Tests Automatisee

Le fichier `server/test-security.js` execute une batterie de 7 tests cryptographiques et fonctionnels verifiant les invariants de securite du systeme :

```bash
node server/test-security.js
```

Sortie d'execution validee :
```text
============================================================
SUITE DE TESTS DE SECURITE AUTOMATISEE - SANTEPLUS SECURE
============================================================

[TEST 1] Rejet requete non authentifiee sur /v1/rdv/:id
   Status: 401 Unauthorized - Rejet conforme.

[TEST 2] Authentification securisee POST /v1/login
   Status: 200 OK - Access Token et Refresh Token emis conformement.

[TEST 3] Rafraichissement de jeton POST /v1/refresh
   Status: 200 OK - Nouveau Access Token genere avec succes.

[TEST 4] Validation stricte UUID v4 sur /v1/rdv/:id (Rejet injection)
   Status: 400 Bad Request - Tentative d'injection bloquee.

[TEST 5] Controle d'acces RBAC - Patient tentant de lire le RDV d'un tiers
   Status: 403 Forbidden - Violation BOLA bloquee par le serveur.

[TEST 6] Controle d'acces RBAC - Admin lisant n'importe quel RDV
   Status: 200 OK - Droits administrateur valides par signature JWT.

[TEST 7] Proxy Google Maps - Masquage de cle API
   Status: 200 OK - Geocodage realise sans fuite de la cle API cote client.

============================================================
RESULTATS : 7/7 TESTS REUSSIS - 0 DEFAILLANCE
============================================================
```

---

### Scenario B : Demonstration Live des Vecteurs d'Attaque Neutralises

Le script `server/demo-exploits.js` simule le comportement d'un attaquant cherchant a exploiter les failles du code historique :

```bash
node server/demo-exploits.js
```

Sortie de demonstration :
```text
================================================================
   DEMONSTRATION D'EXPLOITATION OFFENSIVE VS SANTEPLUS SECURE
================================================================

SCENARIO 1 : Tentative d'authentification en clair (GET query params)
   Attaquant : Pirate sur Wi-Fi public d'hopital (mitmproxy)
   Vecteur   : GET /v1/login?email=patient@santeplus.ma&password=...
   Resultat  : HTTP 404 - Route GET desactivee.
   Defense   : Obligation d'utiliser POST avec TLS et identifiants dans le body JSON.

SCENARIO 2 : Tentative de Path Traversal via Deep Link forge
   Attaquant : SMS malveillant recu par le patient
   Vecteur   : GET /v1/rdv/../../admin
   Resultat  : HTTP 400 - Format d'identifiant de rendez-vous invalide.
   Defense   : Validation regex UUID v4 stricte avant tout traitement.

SCENARIO 3 : Tentative d'acces au dossier medical d'un tiers (BOLA/IDOR)
   Attaquant : Patient connecte (ID: u1)
   Cible     : RDV medical appartenant a u2
   Vecteur   : GET /v1/rdv/6ba7b810-9dad-11d1-80b4-00c04fd430c8
   Resultat  : HTTP 403 - Acces refuse : vous n'etes pas proprietaire de ce rendez-vous.
   Defense   : RBAC backend verifiant la correspondance du userId du JWT.

SCENARIO 4 : Falsification locale du role Admin (Contournement de isAdmin())
   Attaquant : Utilisateur modifiant son stockage local via Frida ou appareil roote
   Tentative : Envoi d'un faux token ou d'un token patient sur ressource protegee
   Resultat  : Rejete avec HTTP 403.
   Defense   : Le serveur ignore l'etat local et verifie la signature cryptographique HMAC.

================================================================
DEMONSTRATION TERMINEE : 100% DES VECTEURS D'ATTAQUE NEUTRALISES
================================================================
```

---

### Scenario C : Validation de la Gestion des Jetons JWT et du Stockage Materiel

1. **Absence de mot de passe sur le terminal :**
   Lors de la connexion dans `src/services/auth.ts`, le mot de passe est transmis au serveur via `POST /v1/login` et n'est jamais sauvegarde. Seuls les jetons retournes sont ecrits dans `expo-secure-store`.
2. **Cloisonnement materiel Keystore / Keychain :**
   Dans `src/services/secureStorage.ts`, l'ecriture s'effectue avec l'option `WHEN_UNLOCKED_THIS_DEVICE_ONLY`, garantissant que les donnees restent inaccessibles lorsque l'ecran est verrouille et empechant leur extraction via des sauvegardes systeme tierces.
3. **Mecanisme de renouvellement transparent :**
   Le jeton d'acces a une duree de vie de 15 minutes. Lorsqu'une requete API echoue avec le code HTTP 401, le client centralise (`src/services/api.ts`) intercepte l'erreur, appelle `POST /v1/refresh` avec le Refresh Token (valable 7 jours), met a jour le stockage securise et rejoue la requete d'origine de maniere transparente pour le patient.

---

### Scenario D : Validation du Controle d'Acces Base sur les Roles (RBAC / BOLA)

1. Authentifiez-vous en tant que patient standard (`patient@santeplus.ma`).
2. Tentez d'acceder au rendez-vous appartenant a un autre utilisateur :
   ```bash
   curl -X GET http://localhost:3000/v1/rdv/6ba7b810-9dad-11d1-80b4-00c04fd430c8 \
     -H "Authorization: Bearer <VOTRE_ACCESS_TOKEN>"
   ```
3. Le serveur analyse le jeton JWT, constate que `userId !== "u2"` et que `role !== "admin"`, et renvoie immediatement un code **HTTP 403 Forbidden**. Le client mobile ne peut en aucun cas forcer l'affichage d'un dossier dont il n'est pas proprietaire.

---

### Scenario E : Validation de l'Authentification Biometrique (Ordonnances)

1. Dans l'application mobile, selectionnez l'onglet **Ordonnances**.
2. L'ecran `src/screens/OrdonnancesScreen.tsx` sollicite immediatement le composant `expo-local-authentication` (`LocalAuthentication.authenticateAsync`).
3. Le contenu des ordonnances medicales n'est jamais charge en clair tant que le capteur d'empreinte digitale ou Face ID n'a pas valide l'identite physique de l'utilisateur.
4. En cas de refus ou d'annulation du prompt biometrique, un message explicatif est presente et aucun fragment de donnees medicales ne reside en memoire applicative.

---

### Scenario F : Validation de l'Etancheite des Deep Links

1. **Test d'injection / Path Traversal :**
   Envoyez un lien forgant un identifiant corrompu :
   ```bash
   npx uri-scheme open "santeplus://rdv?id=../../admin" --android
   ```
   L'expression reguliere de `src/navigation/linking.ts` analyse la chaine `../../admin`, constate la non-conformite avec le gabarit UUID v4, interrompt le traitement et redirige l'utilisateur vers l'accueil sans solliciter le backend.

2. **Test avec identifiant UUID v4 conforme mais sans session :**
   ```bash
   npx uri-scheme open "santeplus://rdv?id=550e8400-e29b-41d4-a716-446655440000" --android
   ```
   Le guard de session verifie la presence d'un jeton actif dans `secureStorage`. Si l'utilisateur est deconnecte, la navigation est deviee vers l'ecran d'authentification (`Login`).

---

### Scenario G : Validation du Durcissement de la WebView (Anti-RCE)

1. Dans `src/screens/ArticleScreen.tsx`, la propriete `originWhitelist={['https://santeplus.ma', 'https://*.santeplus.ma']}` interdit le chargement initial de tout domaine non approuve.
2. Le gestionnaire `onShouldStartLoadWithRequest` intercepte chaque tentative de redirection et bloque immediatement toute URL hors liste blanche.
3. Le gestionnaire de communication `onMessage` parse les charges entrantes via `JSON.parse` et valide l'action demandee contre un ensemble de valeurs strictes (`ALLOWED_ACTIONS`). L'usage de la primitive dangereuse `eval()` est totalement supprime, neutralisant tout risque d'execution de code arbitraire a distance (RCE).

---

### Scenario H : Validation du Proxy Cartographique Google Maps

1. Aucune cle API tierce ne figure dans le bundle binaire client (verifiable par inspection de code ou extraction APK).
2. Toute requete de geolocalisation d'etablissement de sante sollicite l'endpoint du serveur :
   ```bash
   curl -X GET "http://localhost:3000/v1/maps/geocode?address=Casablanca" \
     -H "Authorization: Bearer <VOTRE_ACCESS_TOKEN>"
   ```
3. Le serveur mock SantePlus injecte sa propre variable d'environnement `MAPS_API_KEY` dans l'appel machine-to-machine vers l'infrastructure Google, isolant la cle contre toute tentative de vol ou d'abus de quota.

---

## Conformite Reglementaire : Loi Marocaine 09-08 et CNDP

L'ensemble des mesures techniques mises en oeuvre repond aux exigences de la **Loi marocaine n° 09-08** relative a la protection des personnes physiques a l'egard du traitement des donnees a caractere personnel et aux directives de la **CNDP** :

* **Article 23 (Obligation de securite et de confidentialite) :**
  L'application met en oeuvre des mesures techniques appropriees pour preserver la securite des donnees et empecher qu'elles ne soient deformees, endommagees ou que des tiers non autorises y aient acces. Cela se traduit par le chiffrement materiel au repos (Keystore/Keychain), l'usage exclusif du protocole TLS 1.3 en transit, et la suppression des sauvegardes automatiques Android (`allowBackup=false`).
* **Articles 1 et 12 (Protection renforcee des donnees de sante) :**
  Les donnees relatives a la sante physique, aux prescriptions et aux consultations font l'objet d'un cloisonnement strict. L'acces a l'historique des ordonnances requiert une authentification forte biometrique, conformement au principe de proportionnalite impose pour les donnees sensibles.
* **Article 52 (Sanctions en cas de defaillance de securite) :**
  En eliminant les vulnérabilités majeures identifiees dans l'audit initial (mots de passe en clair, logs de secrets, controle client manipulable), la version durcie de SantePlus met l'organisme gestionnaire en conformite legale, eliminant ainsi les risques d'injonction, d'interdiction de traitement par la CNDP ou de poursuites penales.

---

## Let's Collaborate

* **LinkedIn :** [Salim Elbourmaki](https://www.linkedin.com/in/salim-el-bourmaki-885304373)
* **Portfolio :** [salim1-ai.vercel.app](https://salim1-ai.vercel.app)
* **GitHub :** [@salim-elbourmaki](https://github.com/salim-elbourmaki)
