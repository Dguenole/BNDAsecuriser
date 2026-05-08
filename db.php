<?php
// CORRECTION : Identifiants dans des constantes séparées
define('DB_HOST', 'localhost');
define('DB_NAME', 'bnda_secure');
define('DB_USER', 'root');
define('DB_PASS', '');
define('MAX_ATTEMPTS', 5);
define('LOCK_DURATION', 900); // 15 min

try {
    $pdo = new PDO(
        "mysql:host=".DB_HOST.";dbname=".DB_NAME.";charset=utf8mb4",
        DB_USER, DB_PASS,
        [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ]
    );
} catch (PDOException $e) {
    // CORRECTION : Ne jamais afficher les détails d'erreur DB
    error_log("DB Error: " . $e->getMessage());
    die("Service indisponible. Veuillez réessayer plus tard.");
}

// Échapper les sorties HTML (protection XSS)
function e(string $s): string {
    return htmlspecialchars($s, ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

// Générer / retourner le token CSRF de session
function csrf(): string {
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}

// Valider le token CSRF soumis
function check_csrf(string $token): bool {
    return isset($_SESSION['csrf']) && hash_equals($_SESSION['csrf'], $token);
}

// Journaliser une action de sécurité
function log_action(PDO $pdo, ?int $uid, string $action, string $detail = ''): void {
    $ip = filter_var($_SERVER['REMOTE_ADDR'] ?? '', FILTER_VALIDATE_IP) ?: 'unknown';
    $stmt = $pdo->prepare("INSERT INTO logs (user_id, action, ip, detail) VALUES (?,?,?,?)");
    $stmt->execute([$uid, $action, $ip, $detail]);
}
?>
