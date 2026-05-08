<?php require_once 'auth.php'; ?>
<?php
$uid = (int)$_SESSION['uid'];
$msg = ''; $err = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // CORRECTION CSRF
    if (!check_csrf($_POST['csrf_token'] ?? '')) {
        $err = "Requête invalide (CSRF).";
        log_action($pdo, $uid, 'csrf_virement', 'Token CSRF invalide');
    } else {
        unset($_SESSION['csrf']);

        $src_id  = (int)($_POST['src'] ?? 0);
        $dst_num = trim($_POST['dst'] ?? '');
        $montant = (float)($_POST['montant'] ?? 0);
        $desc    = substr(trim($_POST['description'] ?? ''), 0, 255);

        if ($montant <= 0 || $montant > 99999999) {
            $err = "Montant invalide.";
        } elseif (empty($dst_num)) {
            $err = "Compte destinataire requis.";
        } else {
            // CORRECTION IDOR : Vérifier que le compte source appartient à l'utilisateur
            $s1 = $pdo->prepare("SELECT id, solde FROM comptes WHERE id=? AND user_id=? AND statut='actif'");
            $s1->execute([$src_id, $uid]);
            $src = $s1->fetch();

            // CORRECTION SQLi : Requête préparée pour le compte destination
            $s2 = $pdo->prepare("SELECT id FROM comptes WHERE numero=? AND statut='actif'");
            $s2->execute([$dst_num]);
            $dst = $s2->fetch();

            if (!$src)          { $err = "Compte source invalide."; log_action($pdo, $uid, 'idor_blocked', "Tentative accès compte $src_id"); }
            elseif (!$dst)      { $err = "Compte destinataire introuvable."; }
            elseif ($dst['id'] === $src['id']) { $err = "Source et destination identiques."; }
            elseif ($src['solde'] < $montant)  { $err = "Solde insuffisant."; }
            else {
                // Transaction atomique
                try {
                    $pdo->beginTransaction();
                    $pdo->prepare("UPDATE comptes SET solde=solde-? WHERE id=? AND solde>=?")->execute([$montant, $src['id'], $montant]);
                    $pdo->prepare("UPDATE comptes SET solde=solde+? WHERE id=?")->execute([$montant, $dst['id']]);
                    // CORRECTION XSS stocké : htmlspecialchars avant insertion
                    $pdo->prepare("INSERT INTO virements (compte_src,compte_dst,montant,description) VALUES (?,?,?,?)")
                        ->execute([$src['id'], $dst['id'], $montant, htmlspecialchars($desc, ENT_QUOTES, 'UTF-8')]);
                    $pdo->commit();
                    $msg = "Virement de " . number_format($montant, 0, ',', ' ') . " FCFA effectué.";
                    log_action($pdo, $uid, 'virement_ok', "$montant FCFA → compte {$dst['id']}");
                } catch (Exception $ex) {
                    $pdo->rollBack();
                    $err = "Erreur lors du virement.";
                    error_log($ex->getMessage());
                }
            }
        }
    }
}

// CORRECTION : Seulement les comptes de l'utilisateur connecté
$stmt = $pdo->prepare("SELECT * FROM comptes WHERE user_id=? AND statut='actif'");
$stmt->execute([$uid]);
$mes_comptes = $stmt->fetchAll();

// Historique personnel uniquement
$ids = array_column($mes_comptes, 'id');
$virements = [];
if (!empty($ids)) {
    $ph = implode(',', array_fill(0, count($ids), '?'));
    $s3 = $pdo->prepare(
        "SELECT v.*, cs.numero AS src, cd.numero AS dst
         FROM virements v
         LEFT JOIN comptes cs ON v.compte_src=cs.id
         LEFT JOIN comptes cd ON v.compte_dst=cd.id
         WHERE v.compte_src IN ($ph) OR v.compte_dst IN ($ph)
         ORDER BY v.date_op DESC LIMIT 20"
    );
    $s3->execute(array_merge($ids, $ids));
    $virements = $s3->fetchAll();
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>BNDA – Virement Sécurisé</title>
<style> *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', system-ui, sans-serif; background: #f0f4f8; display: flex; }
  .sidebar { width: 260px; min-height: 100vh; position: fixed; left: 0; top: 0; background: linear-gradient(180deg, #0a1628 0%, #0d1b3e 100%); display: flex; flex-direction: column; box-shadow: 4px 0 24px rgba(0,0,0,0.2); z-index: 100; }
  .sidebar-head { padding: 32px 24px 24px; border-bottom: 1px solid rgba(201,168,76,0.2); }
  .sidebar-head .logo { color: #c9a84c; font-size: 32px; font-weight: 900; letter-spacing: 4px; }
  .sidebar-head .sub { color: rgba(255,255,255,0.4); font-size: 10px; letter-spacing: 1.5px; margin-top: 4px; }
  .nav { padding: 20px 12px; flex: 1; }
  .nav a { display: flex; align-items: center; gap: 12px; padding: 12px 14px; border-radius: 10px; color: rgba(255,255,255,0.6); text-decoration: none; font-size: 14px; font-weight: 500; margin-bottom: 4px; transition: all 0.2s; }
  .nav a:hover, .nav a.active { background: rgba(201,168,76,0.12); color: #c9a84c; }
  .nav-divider { border: none; border-top: 1px solid rgba(255,255,255,0.07); margin: 12px 0; }
  .sidebar-foot { padding: 20px 24px; border-top: 1px solid rgba(255,255,255,0.07); }
  .user-info .name { color: #fff; font-size: 14px; font-weight: 600; }
  .user-info .role { color: #c9a84c; font-size: 11px; text-transform: uppercase; letter-spacing: 1px; }
  .main { margin-left: 260px; flex: 1; }
  .topbar { background: #fff; padding: 18px 32px; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #e8edf3; box-shadow: 0 2px 8px rgba(0,0,0,0.04); }
  .topbar h2 { font-size: 20px; color: #0d1b3e; font-weight: 700; }
  .secure-badge { display: flex; align-items: center; gap: 6px; background: #dcfce7; color: #16a34a; padding: 6px 14px; border-radius: 20px; font-size: 12px; font-weight: 700; }
  .content { padding: 32px; }
  .card { background: #fff; border-radius: 16px; box-shadow: 0 2px 16px rgba(13,27,62,0.07); margin-bottom: 24px; overflow: hidden; }
  .card-head { padding: 18px 24px; border-bottom: 1px solid #f0f4f8; }
  .card-head h3 { font-size: 15px; font-weight: 700; color: #0d1b3e; }
  .card-body { padding: 24px; }
  .grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
  label { display: block; font-size: 13px; font-weight: 600; color: #374151; margin-bottom: 7px; }
  select, input[type=number], input[type=text] { width: 100%; padding: 12px 16px; border: 1.5px solid #e2e8f0; border-radius: 10px; font-size: 14px; background: #f8fafc; color: #1e293b; transition: border 0.2s; }
  select:focus, input:focus { outline: none; border-color: #c9a84c; background: #fff; }
  .btn-submit { margin-top: 20px; padding: 13px 32px; background: linear-gradient(135deg, #0d1b3e, #1a3a7c); color: #fff; font-size: 14px; font-weight: 700; border: none; border-radius: 10px; cursor: pointer; transition: all 0.2s; }
  .btn-submit:hover { transform: translateY(-2px); box-shadow: 0 6px 20px rgba(13,27,62,0.3); }
  .alert-ok  { background: #dcfce7; border-left: 4px solid #16a34a; padding: 14px 18px; border-radius: 10px; color: #15803d; font-weight: 600; margin-bottom: 20px; }
  .alert-err { background: #fff0f0; border-left: 4px solid #dc2626; padding: 14px 18px; border-radius: 10px; color: #b91c1c; margin-bottom: 20px; }
  table { width: 100%; border-collapse: collapse; }
  thead th { padding: 14px 20px; text-align: left; font-size: 12px; color: #94a3b8; font-weight: 600; letter-spacing: 0.5px; text-transform: uppercase; background: #f8fafc; border-bottom: 2px solid #f0f4f8; }
  tbody td { padding: 15px 20px; border-bottom: 1px solid #f8fafc; font-size: 14px; }
  tbody tr:last-child td { border-bottom: none; }
  tbody tr:hover td { background: #fafbff; }
  .amount { font-weight: 700; color: #16a34a; }
</style>
</head>
<body> <aside class="sidebar"> <div class="sidebar-head"> <div class="logo">BNDA</div> <div class="sub">ESPACE CLIENT</div> </div> <nav class="nav"> <a href="home.php">Tableau de bord</a> <a href="virement.php" class="active">Virements</a> <?php if ($_SESSION['role'] === 'admin'): ?> <a href="admin.php">Administration</a> <?php endif; ?> <hr class="nav-divider"> <a href="logout.php">Déconnexion</a> </nav> <div class="sidebar-foot"> <div class="user-info"> <div class="name"><?= e($_SESSION['nom']) ?></div> <div class="role"><?= e($_SESSION['role']) ?></div> </div> </div>
</aside> <main class="main"> <div class="topbar"> <h2> Effectuer un virement</h2> <div class="secure-badge"> Protégé CSRF + SQLi</div> </div> <div class="content"> <?php if ($msg): ?><div class="alert-ok"> <?= e($msg) ?></div><?php endif; ?> <?php if ($err): ?><div class="alert-err"> <?= e($err) ?></div><?php endif; ?> <div class="card"> <div class="card-head"><h3>Nouveau virement sécurisé</h3></div> <div class="card-body"> <form method="POST"> <!-- CORRECTION CSRF : Token unique par formulaire --> <input type="hidden" name="csrf_token" value="<?= csrf() ?>"> <div class="grid2"> <div> <label>Compte source (vos comptes)</label> <select name="src" required> <?php foreach ($mes_comptes as $c): ?> <option value="<?= (int)$c['id'] ?>"><?= e($c['numero']) ?> — <?= number_format($c['solde'],0,',',' ') ?> FCFA</option> <?php endforeach; ?> </select> </div> <div> <label>N° Compte destinataire</label> <!-- CORRECTION : Saisie libre validée côté serveur avec requête préparée --> <input type="text" name="dst" placeholder="Ex: BN-2024-0003"
                     required maxlength="30" pattern="[A-Z0-9\-]+"> </div> </div> <div class="grid2" style="margin-top:16px"> <div> <label>Montant (FCFA)</label> <input type="number" name="montant" placeholder="Ex: 50000" required min="1" max="99999999" step="1"> </div> <div> <label>Description</label> <input type="text" name="description" placeholder="Motif du virement" maxlength="255"> </div> </div> <button type="submit" class="btn-submit">Valider le virement →</button> </form> </div> </div> <div class="card"> <div class="card-head"><h3> Mes virements</h3></div> <table> <thead> <tr><th>Date</th><th>De</th><th>Vers</th><th>Montant</th><th>Description</th></tr> </thead> <tbody> <?php foreach ($virements as $v): ?> <tr> <td style="color:#64748b"><?= e($v['date_op']) ?></td> <td><?= e($v['src'] ?? '—') ?></td> <td><?= e($v['dst'] ?? '—') ?></td> <td class="amount"><?= number_format($v['montant'],0,',',' ') ?> FCFA</td> <td><?= e($v['description'] ?? '') ?></td> </tr> <?php endforeach; ?> </tbody> </table> </div> </div>
</main>
</body>
</html>
