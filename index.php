<?php
// CORRECTION : Configuration sécurisée de la session
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 0);    // Mettre 1 en production HTTPS
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.use_strict_mode', 1);
session_start();

if (isset($_SESSION['uid'])) { header("Location: home.php"); exit; }
require_once 'db.php';

// CORRECTION XSS : Les messages passent par la session, jamais par $_GET
$err     = $_SESSION['err'] ?? '';
$success = $_SESSION['ok']  ?? '';
unset($_SESSION['err'], $_SESSION['ok']);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // CORRECTION CSRF
    if (!check_csrf($_POST['csrf_token'] ?? '')) {
        $_SESSION['err'] = "Requête invalide.";
        log_action($pdo, null, 'csrf_fail', 'Token invalide sur login');
        header("Location: index.php"); exit;
    }
    unset($_SESSION['csrf']);

    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';

    // Validation format
    if (!preg_match('/^[a-zA-Z0-9_]{3,50}$/', $username) || empty($password)) {
        $_SESSION['err'] = "Identifiants invalides.";
        header("Location: index.php"); exit;
    }

    // CORRECTION SQLi : Requête préparée
    $stmt = $pdo->prepare("SELECT id,nom,username,password_hash,role,tentatives,verrou_fin FROM users WHERE username=?");
    $stmt->execute([$username]);
    $user = $stmt->fetch();

    if ($user) {
        // Anti brute-force : vérifier le verrouillage
        if ($user['verrou_fin'] && strtotime($user['verrou_fin']) > time()) {
            $min = ceil((strtotime($user['verrou_fin']) - time()) / 60);
            $_SESSION['err'] = "Compte bloqué. Réessayez dans $min minute(s).";
            log_action($pdo, $user['id'], 'login_blocked', "Tentative sur compte verrouillé");
            header("Location: index.php"); exit;
        }

        // CORRECTION : Vérification bcrypt (résistant timing-attack)
        if (password_verify($password, $user['password_hash'])) {
            // CORRECTION Session Fixation : régénérer l'ID après authentification
            session_regenerate_id(true);
            $_SESSION['uid']  = $user['id'];
            $_SESSION['nom']  = $user['nom'];
            $_SESSION['role'] = $user['role'];
            $_SESSION['ip']   = $_SERVER['REMOTE_ADDR'] ?? '';
            $_SESSION['last'] = time();

            $pdo->prepare("UPDATE users SET tentatives=0, verrou_fin=NULL WHERE id=?")->execute([$user['id']]);
            log_action($pdo, $user['id'], 'login_ok', '');
            header("Location: home.php"); exit;
        } else {
            $t = $user['tentatives'] + 1;
            if ($t >= MAX_ATTEMPTS) {
                $fin = date('Y-m-d H:i:s', time() + LOCK_DURATION);
                $pdo->prepare("UPDATE users SET tentatives=?, verrou_fin=? WHERE id=?")->execute([$t, $fin, $user['id']]);
                $_SESSION['err'] = "Trop de tentatives. Compte bloqué 15 minutes.";
                log_action($pdo, $user['id'], 'account_locked', "$t tentatives");
            } else {
                $pdo->prepare("UPDATE users SET tentatives=? WHERE id=?")->execute([$t, $user['id']]);
                // CORRECTION : Message générique (pas d'énumération d'utilisateurs)
                $_SESSION['err'] = "Identifiants incorrects.";
                log_action($pdo, $user['id'], 'login_fail', "Tentative $t/".MAX_ATTEMPTS);
            }
        }
    } else {
        // Même temps de réponse même si user inexistant (timing attack)
        password_verify($password, '$2y$10$fakehashpaddingtomatch60charstotal12345678901234567890');
        $_SESSION['err'] = "Identifiants incorrects.";
        log_action($pdo, null, 'login_fail', "Username inconnu: $username");
    }
    header("Location: index.php"); exit;
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>BNDA – Connexion Sécurisée</title>
<style> *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Segoe UI', system-ui, sans-serif;
    min-height: 100vh; display: flex; background: #0a1628;
  }
  .left {
    flex: 1;
    background: linear-gradient(160deg, #0d1b3e 0%, #1a3a7c 60%, #0a2d5e 100%);
    display: flex; flex-direction: column;
    align-items: center; justify-content: center;
    padding: 60px 40px; position: relative; overflow: hidden;
  }
  .left::before {
    content: '';
    position: absolute; inset: 0;
    background: url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23ffffff' fill-opacity='0.03'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E");
  }
  .brand-logo { color: #c9a84c; font-size: 64px; font-weight: 900; letter-spacing: 6px; text-shadow: 0 4px 20px rgba(201,168,76,0.4); }
  .brand-sub { color: rgba(255,255,255,0.7); font-size: 13px; letter-spacing: 2px; text-transform: uppercase; margin-top: 8px; text-align: center; }
  .brand-desc { margin-top: 40px; color: rgba(255,255,255,0.45); font-size: 14px; line-height: 1.8; text-align: center; max-width: 340px; }
  .shield { width: 80px; height: 80px; margin-bottom: 20px; background: rgba(201,168,76,0.15); border-radius: 50%; display: flex; align-items: center; justify-content: center; border: 2px solid rgba(201,168,76,0.3); font-size: 36px; }
  .secure-pills { display: flex; gap: 10px; margin-top: 36px; flex-wrap: wrap; justify-content: center; }
  .pill { background: rgba(255,255,255,0.07); border: 1px solid rgba(255,255,255,0.12); color: rgba(255,255,255,0.6); padding: 6px 14px; border-radius: 20px; font-size: 12px; }
  .right { width: 480px; background: #fff; display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 60px 56px; }
  .secure-tag { display: flex; align-items: center; gap: 6px; background: #dcfce7; color: #16a34a; padding: 6px 16px; border-radius: 20px; font-size: 12px; font-weight: 700; margin-bottom: 28px; }
  .form-title { font-size: 26px; font-weight: 700; color: #0d1b3e; margin-bottom: 6px; }
  .form-sub { color: #64748b; font-size: 14px; margin-bottom: 32px; }
  .form-group { width: 100%; margin-bottom: 20px; }
  label { display: block; font-size: 13px; font-weight: 600; color: #374151; margin-bottom: 7px; }
  input[type=text], input[type=password] { width: 100%; padding: 13px 16px; border: 1.5px solid #e2e8f0; border-radius: 10px; font-size: 14px; color: #1e293b; background: #f8fafc; transition: border 0.2s, background 0.2s; }
  input:focus { outline: none; border-color: #c9a84c; background: #fff; }
  .btn-login { width: 100%; padding: 14px; background: linear-gradient(135deg, #0d1b3e, #1a3a7c); color: #fff; font-size: 15px; font-weight: 700; border: none; border-radius: 10px; cursor: pointer; transition: transform 0.2s, box-shadow 0.2s; letter-spacing: 0.5px; margin-top: 8px; }
  .btn-login:hover { transform: translateY(-2px); box-shadow: 0 8px 24px rgba(13,27,62,0.35); }
  .alert-err { width: 100%; padding: 12px 16px; background: #fff0f0; border-left: 4px solid #dc2626; border-radius: 8px; color: #b91c1c; font-size: 14px; margin-bottom: 20px; }
  .alert-ok  { width: 100%; padding: 12px 16px; background: #f0fdf4; border-left: 4px solid #16a34a; border-radius: 8px; color: #15803d; font-size: 14px; margin-bottom: 20px; }
  .divider { border: none; border-top: 1px solid #f0f4f8; margin: 28px 0; width: 100%; }
  .footer-note { color: #94a3b8; font-size: 12px; text-align: center; }
  @media(max-width: 768px) { .left { display: none; } .right { width: 100%; padding: 40px 28px; } }
</style>
</head>
<body> <div class="left"> <div class="shield"></div> <div class="brand-logo">BNDA</div> <div class="brand-sub">Banque Nationale de Développement Agricole</div> <p class="brand-desc">Votre partenaire financier de confiance.<br>Gérez vos comptes, effectuez vos virements<br>et suivez vos transactions en temps réel.</p> <div class="secure-pills"> <span class="pill"> TLS 1.3</span> <span class="pill"> WAF</span> <span class="pill"> bcrypt</span> <span class="pill"> OWASP</span> <span class="pill"> ISO 27001</span> </div>
</div> <div class="right"> <div class="secure-tag"> Connexion sécurisée</div> <h1 class="form-title">Bon retour </h1> <p class="form-sub">Connectez-vous à votre espace client</p> <!-- CORRECTION XSS : Utilisation de e() pour échapper les messages --> <?php if ($err): ?> <div class="alert-err"> <?= e($err) ?></div> <?php endif; ?> <?php if ($success): ?> <div class="alert-ok"> <?= e($success) ?></div> <?php endif; ?> <form method="POST" style="width:100%" autocomplete="off"> <!-- CORRECTION CSRF : Token dans chaque formulaire --> <input type="hidden" name="csrf_token" value="<?= csrf() ?>"> <div class="form-group"> <label>Nom d'utilisateur</label> <input type="text" name="username" placeholder="Votre identifiant"
             required maxlength="50" pattern="[a-zA-Z0-9_]+" autocomplete="off"> </div> <div class="form-group"> <label>Mot de passe</label> <input type="password" name="password" placeholder="••••••••"
             required maxlength="128" autocomplete="off"> </div> <button type="submit" class="btn-login">Se connecter</button> </form> <hr class="divider"> <p class="footer-note">© 2024 BNDA · Connexion chiffrée HTTPS</p>
</div> </body>
</html>
