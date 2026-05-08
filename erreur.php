<?php
$c = (int)($_GET['c'] ?? 404);
$msgs = [
    400 => ['400', 'Requête invalide', 'La requête envoyée est incorrecte.'],
    401 => ['401', 'Non autorisé', 'Authentification requise.'],
    403 => ['403', 'Accès interdit', "Vous n'avez pas les droits nécessaires."],
    404 => ['404', 'Page introuvable', 'La page demandée n\'existe pas.'],
    500 => ['500', 'Erreur serveur', 'Une erreur interne s\'est produite. L\'équipe technique a été alertée.'],
];
$info = $msgs[$c] ?? ['Erreur', 'Erreur', 'Une erreur s\'est produite.'];
http_response_code($c);
?>
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>BNDA – Erreur <?= $info[0] ?></title>
<style> body { font-family: 'Segoe UI', system-ui, sans-serif; background: #f0f4f8; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
  .box { text-align: center; background: #fff; padding: 60px 48px; border-radius: 20px; box-shadow: 0 8px 40px rgba(13,27,62,0.1); max-width: 460px; }
  .code { font-size: 80px; font-weight: 900; color: #c9a84c; line-height: 1; }
  h2 { color: #0d1b3e; margin: 16px 0 8px; font-size: 22px; }
  p { color: #64748b; font-size: 14px; margin-bottom: 28px; }
  a { display: inline-block; padding: 12px 28px; background: linear-gradient(135deg,#0d1b3e,#1a3a7c); color: #fff; border-radius: 10px; text-decoration: none; font-weight: 700; font-size: 14px; }
</style>
</head>
<body> <div class="box"> <div class="code"><?= $info[0] ?></div> <h2><?= htmlspecialchars($info[1]) ?></h2> <p><?= htmlspecialchars($info[2]) ?></p> <a href="index.php">← Retour à l'accueil</a> </div>
</body>
</html>
