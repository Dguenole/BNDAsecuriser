<?php require_once 'auth.php'; ?>
<?php
$uid = (int)$_SESSION['uid'];

// CORRECTION IDOR : Filtre strict par user_id — impossible d'accéder aux comptes d'autrui
$stmt = $pdo->prepare("SELECT * FROM comptes WHERE user_id=? AND statut='actif'");
$stmt->execute([$uid]);
$comptes = $stmt->fetchAll();
$solde_total = array_sum(array_column($comptes, 'solde'));

// Virements uniquement liés aux comptes de l'utilisateur
$ids = array_column($comptes, 'id');
$virements = [];
if (!empty($ids)) {
    $ph = implode(',', array_fill(0, count($ids), '?'));
    $s2 = $pdo->prepare(
        "SELECT v.*, cs.numero AS src, cd.numero AS dst
         FROM virements v
         LEFT JOIN comptes cs ON v.compte_src=cs.id
         LEFT JOIN comptes cd ON v.compte_dst=cd.id
         WHERE v.compte_src IN ($ph) OR v.compte_dst IN ($ph)
         ORDER BY v.date_op DESC LIMIT 8"
    );
    $s2->execute(array_merge($ids, $ids));
    $virements = $s2->fetchAll();
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>BNDA – Tableau de bord</title>
<style> *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', system-ui, sans-serif; background: #f0f4f8; display: flex; }
  .sidebar {
    width: 260px; min-height: 100vh; position: fixed; left: 0; top: 0;
    background: linear-gradient(180deg, #0a1628 0%, #0d1b3e 100%);
    display: flex; flex-direction: column;
    box-shadow: 4px 0 24px rgba(0,0,0,0.2); z-index: 100;
  }
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
  .stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-bottom: 28px; }
  .stat-card { border-radius: 16px; padding: 24px 28px; position: relative; overflow: hidden; cursor: default; transition: transform 0.2s; }
  .stat-card:hover { transform: translateY(-3px); }
  .stat-card.navy { background: linear-gradient(135deg, #0d1b3e 0%, #1a3a7c 100%); }
  .stat-card.gold  { background: linear-gradient(135deg, #92711d 0%, #c9a84c 100%); }
  .stat-card.green { background: linear-gradient(135deg, #145214 0%, #2e7d32 100%); }
  .stat-card::after { content: ''; position: absolute; width: 120px; height: 120px; border-radius: 50%; background: rgba(255,255,255,0.06); bottom: -30px; right: -20px; }
  .stat-label { color: rgba(255,255,255,0.65); font-size: 12px; letter-spacing: 0.5px; margin-bottom: 10px; }
  .stat-value { color: #fff; font-size: 26px; font-weight: 800; }
  .stat-icon { position: absolute; top: 20px; right: 24px; font-size: 28px; opacity: 0.25; }
  .card { background: #fff; border-radius: 16px; box-shadow: 0 2px 16px rgba(13,27,62,0.07); margin-bottom: 24px; overflow: hidden; }
  .card-head { padding: 18px 24px; border-bottom: 1px solid #f0f4f8; display: flex; justify-content: space-between; align-items: center; }
  .card-head h3 { font-size: 15px; font-weight: 700; color: #0d1b3e; }
  table { width: 100%; border-collapse: collapse; }
  thead th { padding: 14px 20px; text-align: left; font-size: 12px; color: #94a3b8; font-weight: 600; letter-spacing: 0.5px; text-transform: uppercase; background: #f8fafc; border-bottom: 2px solid #f0f4f8; }
  tbody td { padding: 15px 20px; border-bottom: 1px solid #f8fafc; color: #1e293b; font-size: 14px; }
  tbody tr:last-child td { border-bottom: none; }
  tbody tr:hover td { background: #fafbff; }
  .badge { display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; }
  .badge-actif  { background: #dcfce7; color: #16a34a; }
  .badge-bloque { background: #fee2e2; color: #dc2626; }
  .badge-type   { background: #e0f2fe; color: #0369a1; }
  .amount { font-weight: 700; color: #16a34a; }
</style>
</head>
<body> <aside class="sidebar"> <div class="sidebar-head"> <div class="logo">BNDA</div> <div class="sub">ESPACE CLIENT</div> </div> <nav class="nav"> <a href="home.php" class="active">Tableau de bord</a> <a href="virement.php">Virements</a> <?php if ($_SESSION['role'] === 'admin'): ?> <a href="admin.php">Administration</a> <?php endif; ?> <hr class="nav-divider"> <a href="logout.php">Déconnexion</a> </nav> <div class="sidebar-foot"> <div class="user-info"> <!-- CORRECTION XSS : e() sur toutes les sorties --> <div class="name"><?= e($_SESSION['nom']) ?></div> <div class="role"><?= e($_SESSION['role']) ?></div> </div> </div>
</aside> <main class="main"> <div class="topbar"> <h2>Tableau de bord</h2> <div class="secure-badge"> Session sécurisée</div> </div> <div class="content"> <div class="stats"> <div class="stat-card navy"> <span class="stat-icon"></span> <div class="stat-label">SOLDE TOTAL</div> <div class="stat-value"><?= number_format($solde_total, 0, ',', ' ') ?> FCFA</div> </div> <div class="stat-card gold"> <span class="stat-icon"></span> <div class="stat-label">COMPTES ACTIFS</div> <div class="stat-value"><?= count($comptes) ?></div> </div> <div class="stat-card green"> <span class="stat-icon"></span> <div class="stat-label">OPÉRATIONS</div> <div class="stat-value"><?= count($virements) ?></div> </div> </div> <div class="card"> <div class="card-head"> <h3> Mes comptes bancaires</h3> <span style="font-size:12px;color:#94a3b8">Accès restreint à vos comptes uniquement</span> </div> <table> <thead> <tr><th>N° Compte</th><th>Type</th><th>Solde</th><th>Statut</th></tr> </thead> <tbody> <?php foreach ($comptes as $c): ?> <tr> <td><strong><?= e($c['numero']) ?></strong></td> <td><span class="badge badge-type"><?= e(ucfirst($c['type'])) ?></span></td> <td class="amount"><?= number_format($c['solde'], 2, ',', ' ') ?> FCFA</td> <td><span class="badge badge-<?= e($c['statut']) ?>"><?= e($c['statut']) ?></span></td> </tr> <?php endforeach; ?> </tbody> </table> </div> <div class="card"> <div class="card-head"><h3> Mes derniers virements</h3></div> <table> <thead> <tr><th>Date</th><th>De</th><th>Vers</th><th>Montant</th><th>Description</th></tr> </thead> <tbody> <?php foreach ($virements as $v): ?> <tr> <td style="color:#64748b"><?= e($v['date_op']) ?></td> <td><?= e($v['src'] ?? '—') ?></td> <td><?= e($v['dst'] ?? '—') ?></td> <td class="amount"><?= number_format($v['montant'], 0, ',', ' ') ?> FCFA</td> <!-- CORRECTION XSS Stocké : e() sur la description --> <td><?= e($v['description'] ?? '') ?></td> </tr> <?php endforeach; ?> </tbody> </table> </div> </div>
</main>
</body>
</html>
