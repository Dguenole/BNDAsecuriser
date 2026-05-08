CREATE DATABASE IF NOT EXISTS bnda_secure CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE bnda_secure;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nom VARCHAR(100) NOT NULL,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(150) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,       -- bcrypt hash
    role ENUM('admin','client') DEFAULT 'client',
    tentatives TINYINT DEFAULT 0,              -- anti brute-force
    verrou_fin DATETIME DEFAULT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE comptes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    numero VARCHAR(20) UNIQUE NOT NULL,
    type ENUM('courant','epargne') DEFAULT 'courant',
    solde DECIMAL(15,2) DEFAULT 0.00,
    statut ENUM('actif','bloque') DEFAULT 'actif',
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE virements (
    id INT AUTO_INCREMENT PRIMARY KEY,
    compte_src INT,
    compte_dst INT,
    montant DECIMAL(15,2) NOT NULL,
    description VARCHAR(255),
    date_op DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (compte_src) REFERENCES comptes(id),
    FOREIGN KEY (compte_dst) REFERENCES comptes(id)
);

-- Table de journalisation sécurité
CREATE TABLE logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT DEFAULT NULL,
    action VARCHAR(100) NOT NULL,
    ip VARCHAR(45),
    detail TEXT,
    date_action DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX (date_action)
);

-- Mots de passe hashés avec password_hash($pass, PASSWORD_BCRYPT)
-- Tous les mots de passe de test = "password" (hash bcrypt)
INSERT INTO users (nom, username, email, password_hash, role) VALUES
('Administrateur BNDA', 'admin',    'admin@bnda.ml',       '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'admin'),
('Coulibaly Ibrahim',   'ibrahim',  'ibrahim@gmail.com',   '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'client'),
('Diallo Fatoumata',    'fatoumata','fatoumata@gmail.com', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'client'),
('Traoré Moussa',       'moussa',   'moussa@gmail.com',    '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'client');

INSERT INTO comptes (user_id, numero, type, solde) VALUES
(2, 'BN-2024-0001', 'courant', 2500000.00),
(2, 'BN-2024-0002', 'epargne',  800000.00),
(3, 'BN-2024-0003', 'courant', 1750000.00),
(4, 'BN-2024-0004', 'courant',  430000.00);

INSERT INTO virements (compte_src, compte_dst, montant, description) VALUES
(1, 3, 150000, 'Paiement facture'),
(3, 1, 50000,  'Remboursement prêt'),
(2, 4, 200000, 'Virement famille');
