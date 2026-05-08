<?php
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_samesite', 'Strict');
session_start();
require_once 'db.php';

if (isset($_SESSION['uid'])) {
    log_action($pdo, (int)$_SESSION['uid'], 'logout', 'Déconnexion');
}

// CORRECTION : Destruction complète de la session
$_SESSION = [];
if (ini_get("session.use_cookies")) {
    $p = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000, $p["path"], $p["domain"], $p["secure"], $p["httponly"]);
}
session_destroy();

// Démarrer une nouvelle session propre pour le message
session_start();
session_regenerate_id(true);
$_SESSION['ok'] = "Vous avez été déconnecté avec succès.";

header("Location: index.php"); exit;
?>
