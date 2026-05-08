<?php
// Inclure dans chaque page protégée

ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 0); // Mettre 1 en production HTTPS
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.use_strict_mode', 1);

if (session_status() === PHP_SESSION_NONE) session_start();

require_once __DIR__ . '/db.php';

// Vérifier que la session est active et non expirée
if (!isset($_SESSION['uid'])) {
    header("Location: index.php"); exit;
}

// CORRECTION Session Hijacking : lier la session à l'IP
if (isset($_SESSION['ip']) && $_SESSION['ip'] !== ($_SERVER['REMOTE_ADDR'] ?? '')) {
    session_destroy();
    header("Location: index.php"); exit;
}

// Expiration après 30 min d'inactivité
if (isset($_SESSION['last']) && (time() - $_SESSION['last']) > 1800) {
    session_destroy();
    header("Location: index.php"); exit;
}
$_SESSION['last'] = time();

// Vérifier le rôle admin directement en base (pas seulement en session)
function require_admin(PDO $pdo): void {
    $stmt = $pdo->prepare("SELECT role FROM users WHERE id=?");
    $stmt->execute([$_SESSION['uid']]);
    $u = $stmt->fetch();
    if (!$u || $u['role'] !== 'admin') {
        header("Location: home.php"); exit;
    }
}

// En-têtes de sécurité HTTP
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data:; frame-ancestors 'none';");
?>
