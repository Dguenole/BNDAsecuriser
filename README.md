# BNDAsecuriser

Application web bancaire PHP sécurisée, développée comme démonstration des bonnes pratiques OWASP pour la **Banque Nationale de Développement Agricole (BNDA)**.

## Fonctionnalités

- Authentification sécurisée avec verrouillage après 5 tentatives (15 min)
- Espace client : consultation des comptes et historique des virements
- Panel administrateur : gestion des utilisateurs et des comptes
- Journal d'audit complet de toutes les actions de sécurité

## Mesures de sécurité implémentées

| Menace | Contre-mesure |
|--------|---------------|
| SQL Injection | Requêtes préparées PDO |
| XSS | Échappement systématique via `htmlspecialchars()` |
| CSRF | Token de session validé sur chaque formulaire POST |
| Brute-force | Compteur de tentatives + verrouillage temporaire |
| Session Fixation | `session_regenerate_id(true)` après connexion |
| Timing Attack | `password_verify()` à durée constante + fake hash |
| Énumération d'utilisateurs | Message d'erreur générique unique |
| Fuites d'erreurs DB | Logs serveur uniquement, pas d'affichage utilisateur |

## Stack technique

- **Backend** : PHP 8+ / PDO / MySQL
- **Hachage** : bcrypt (`PASSWORD_BCRYPT`)
- **Session** : `HttpOnly`, `SameSite=Strict`, mode strict

## Installation

```bash
# 1. Cloner le dépôt dans votre répertoire web
git clone https://github.com/Dguenole/BNDAsecuriser.git

# 2. Importer la base de données
mysql -u root -p < bnda_secure.sql

# 3. Configurer db.php si nécessaire (host, user, pass)
```

> Activer `session.cookie_secure = 1` et HTTPS en production.

## Comptes de test

| Rôle | Username | Mot de passe |
|------|----------|--------------|
| Admin | `admin` | `password` |
| Client | `ibrahim` | `password` |
| Client | `fatoumata` | `password` |
| Client | `moussa` | `password` |

## Structure

```
BNDAsecuriser/
├── index.php       # Page de connexion
├── home.php        # Tableau de bord client
├── virement.php    # Formulaire de virement
├── admin.php       # Panel administrateur
├── auth.php        # Vérification de session
├── db.php          # Connexion PDO + fonctions utilitaires
├── logout.php      # Déconnexion sécurisée
├── erreur.php      # Page d'erreur générique
├── .htaccess       # Headers de sécurité HTTP
└── bnda_secure.sql # Schéma et données de test
```
