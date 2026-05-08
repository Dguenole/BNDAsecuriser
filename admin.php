<?php
require_once 'auth.php';
require_admin($pdo);

$msg = ''; $err = '';
$action = $_GET['action'] ?? '';
$edit_user = null;

// ══ SUPPRIMER ═════════════════════════════════════════════
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'delete') {
    if (!check_csrf($_POST['csrf_token'] ?? '')) {
        $err = "Requête invalide.";
    } else {
        unset($_SESSION['csrf']);
        $target = (int)$_POST['user_id'];
        if ($target === (int)$_SESSION['uid']) {
            $err = "Impossible de supprimer votre propre compte.";
        } else {
            $stmt = $pdo->prepare("DELETE FROM users WHERE id=? AND role='client'");
            $stmt->execute([$target]);
            if ($stmt->rowCount()) {
                $msg = "Utilisateur supprimé.";
                log_action($pdo, $_SESSION['uid'], 'user_deleted', "ID $target");
            } else {
                $err = "Suppression impossible (admin protégé ou introuvable).";
            }
        }
    }
    $action = '';
}

// ══ CRÉER ══════════════════════════════════════════════════
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'create') {
    if (!check_csrf($_POST['csrf_token'] ?? '')) {
        $err = "Requête invalide.";
    } else {
        unset($_SESSION['csrf']);

        $nom      = trim($_POST['nom'] ?? '');
        $username = trim($_POST['username'] ?? '');
        $email    = trim($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';
        $role     = in_array($_POST['role'], ['admin','client']) ? $_POST['role'] : 'client';

        // Validation
        if (strlen($nom) < 3 || strlen($nom) > 100)            $err = "Nom invalide (3-100 caractères).";
        elseif (!preg_match('/^[a-zA-Z0-9_]{3,50}$/', $username)) $err = "Username invalide (lettres, chiffres, _ uniquement).";
        elseif (!filter_var($email, FILTER_VALIDATE_EMAIL))        $err = "Email invalide.";
        elseif (strlen($password) < 8)                            $err = "Mot de passe trop court (8 min).";
        else {
            // Vérifier unicité username/email
            $chk = $pdo->prepare("SELECT id FROM users WHERE username=? OR email=?");
            $chk->execute([$username, $email]);
            if ($chk->fetch()) {
                $err = "Username ou email déjà utilisé.";
            } else {
                $hash = password_hash($password, PASSWORD_BCRYPT);
                $stmt = $pdo->prepare("INSERT INTO users (nom,username,email,password_hash,role) VALUES (?,?,?,?,?)");
                $stmt->execute([$nom, $username, $email, $hash, $role]);
                $msg = "Utilisateur créé avec succès.";
                log_action($pdo, $_SESSION['uid'], 'user_created', "Username: $username");
            }
        }
    }
    $action = ($err ? 'create' : '');
}

// ══ MODIFIER ═══════════════════════════════════════════════
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'update') {
    if (!check_csrf($_POST['csrf_token'] ?? '')) {
        $err = "Requête invalide.";
    } else {
        unset($_SESSION['csrf']);

        $id       = (int)$_POST['id'];
        $nom      = trim($_POST['nom'] ?? '');
        $username = trim($_POST['username'] ?? '');
        $email    = trim($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';
        $role     = in_array($_POST['role'], ['admin','client']) ? $_POST['role'] : 'client';

        if (strlen($nom) < 3 || strlen($nom) > 100)               $err = "Nom invalide.";
        elseif (!preg_match('/^[a-zA-Z0-9_]{3,50}$/', $username))  $err = "Username invalide.";
        elseif (!filter_var($email, FILTER_VALIDATE_EMAIL))         $err = "Email invalide.";
        else {
            // Vérifier unicité en excluant l'utilisateur courant
            $chk = $pdo->prepare("SELECT id FROM users WHERE (username=? OR email=?) AND id!=?");
            $chk->execute([$username, $email, $id]);
            if ($chk->fetch()) {
                $err = "Username ou email déjà utilisé par un autre compte.";
            } else {
                if (!empty($password)) {
                    // Mot de passe fourni → le mettre à jour
                    if (strlen($password) < 8) {
                        $err = "Mot de passe trop court (8 min).";
                    } else {
                        $hash = password_hash($password, PASSWORD_BCRYPT);
                        $stmt = $pdo->prepare("UPDATE users SET nom=?,username=?,email=?,password_hash=?,role=? WHERE id=?");
                        $stmt->execute([$nom, $username, $email, $hash, $role, $id]);
                    }
                } else {
                    // Pas de nouveau mot de passe → ne pas toucher au hash
                    $stmt = $pdo->prepare("UPDATE users SET nom=?,username=?,email=?,role=? WHERE id=?");
                    $stmt->execute([$nom, $username, $email, $role, $id]);
                }
                if (!$err) {
                    $msg = "Utilisateur modifié.";
                    log_action($pdo, $_SESSION['uid'], 'user_updated', "ID $id");
                }
            }
        }
        if ($err) { $action = 'edit'; }
    }
}

// Charger l'utilisateur à éditer
if ($action === 'edit' && isset($_GET['id'])) {
    $stmt = $pdo->prepare("SELECT id,nom,username,email,role FROM users WHERE id=?");
    $stmt->execute([(int)$_GET['id']]);
    $edit_user = $stmt->fetch();
    if (!$edit_user) { $action = ''; $err = "Utilisateur introuvable."; }
}
// Si erreur en update, recharger depuis POST
if ($action === 'edit' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $edit_user = ['id'=>$_POST['id'],'nom'=>$_POST['nom'],'username'=>$_POST['username'],'email'=>$_POST['email'],'role'=>$_POST['role']];
}

// Liste des utilisateurs
$q    = trim($_GET['q'] ?? '');
$like = '%' . $q . '%';
$stmt = $pdo->prepare("SELECT id,nom,username,email,role,created_at FROM users WHERE nom LIKE ? OR username LIKE ? ORDER BY id");
$stmt->execute([$like, $like]);
$users = $stmt->fetchAll();

$r2 = $pdo->prepare("SELECT c.*,u.username FROM comptes c JOIN users u ON c.user_id=u.id ORDER BY c.id");
$r2->execute();
$comptes = $r2->fetchAll();

$r3 = $pdo->prepare("SELECT * FROM logs ORDER BY date_action DESC LIMIT 30");
$r3->execute();
$logs = $r3->fetchAll();
?>
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>BNDA – Administration Sécurisée</title>
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
  .secure-badge { background: #dcfce7; color: #16a34a; padding: 6px 14px; border-radius: 20px; font-size: 12px; font-weight: 700; }
  .content { padding: 32px; }
  .card { background: #fff; border-radius: 16px; box-shadow: 0 2px 16px rgba(13,27,62,0.07); margin-bottom: 24px; overflow: hidden; }
  .card-head { padding: 18px 24px; border-bottom: 1px solid #f0f4f8; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px; }
  .card-head h3 { font-size: 15px; font-weight: 700; color: #0d1b3e; }
  .card-body { padding: 24px; }
  .grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
  .grid3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 16px; }
  .form-group { display: flex; flex-direction: column; }
  label { font-size: 13px; font-weight: 600; color: #374151; margin-bottom: 6px; }
  input[type=text], input[type=email], input[type=password], select {
    width: 100%; padding: 11px 14px; border: 1.5px solid #e2e8f0;
    border-radius: 9px; font-size: 14px; background: #f8fafc; color: #1e293b; transition: border 0.2s;
  }
  input:focus, select:focus { outline: none; border-color: #c9a84c; background: #fff; }
  .hint { font-size: 11px; color: #94a3b8; margin-top: 4px; }
  .btn { padding: 10px 22px; border-radius: 9px; font-size: 13px; font-weight: 700; border: none; cursor: pointer; transition: all 0.2s; text-decoration: none; display: inline-flex; align-items: center; gap: 5px; }
  .btn-primary { background: linear-gradient(135deg,#0d1b3e,#1a3a7c); color: #fff; }
  .btn-primary:hover { transform: translateY(-1px); box-shadow: 0 4px 14px rgba(13,27,62,0.3); }
  .btn-gold { background: #c9a84c; color: #fff; }
  .btn-gold:hover { background: #b8973b; }
  .btn-danger { background: #dc2626; color: #fff; font-size: 12px; padding: 6px 13px; }
  .btn-danger:hover { background: #b91c1c; }
  .btn-edit { background: #0369a1; color: #fff; font-size: 12px; padding: 6px 13px; }
  .btn-edit:hover { background: #0284c7; }
  .btn-cancel { background: #f1f5f9; color: #475569; }
  .btn-cancel:hover { background: #e2e8f0; }
  .search-row { display: flex; gap: 10px; }
  .search-row input { padding: 9px 14px; border: 1.5px solid #e2e8f0; border-radius: 8px; font-size: 13px; background: #f8fafc; width: 200px; }
  .search-row button { padding: 9px 16px; background: #0d1b3e; color: #fff; border: none; border-radius: 8px; cursor: pointer; font-size: 13px; }
  table { width: 100%; border-collapse: collapse; }
  thead th { padding: 13px 18px; text-align: left; font-size: 11px; color: #94a3b8; font-weight: 600; letter-spacing: 0.5px; text-transform: uppercase; background: #f8fafc; border-bottom: 2px solid #f0f4f8; }
  tbody td { padding: 13px 18px; border-bottom: 1px solid #f8fafc; font-size: 14px; color: #1e293b; }
  tbody tr:last-child td { border-bottom: none; }
  tbody tr:hover td { background: #fafbff; }
  .badge { display: inline-block; padding: 3px 10px; border-radius: 20px; font-size: 11px; font-weight: 700; }
  .badge-admin  { background: #fee2e2; color: #dc2626; }
  .badge-client { background: #e0f2fe; color: #0369a1; }
  .badge-actif  { background: #dcfce7; color: #16a34a; }
  .badge-ok     { background: #f0fdf4; color: #16a34a; }
  .badge-danger { background: #fff1f2; color: #e11d48; }
  .amount { font-weight: 700; color: #16a34a; }
  .alert-ok  { background: #dcfce7; border-left: 4px solid #16a34a; padding: 13px 18px; border-radius: 10px; color: #15803d; font-weight: 600; margin-bottom: 20px; font-size: 14px; }
  .alert-err { background: #fff0f0; border-left: 4px solid #dc2626; padding: 13px 18px; border-radius: 10px; color: #b91c1c; margin-bottom: 20px; font-size: 14px; }
  .form-actions { display: flex; gap: 10px; margin-top: 20px; }
  .scroll-table { max-height: 300px; overflow-y: auto; }
  .log-danger td { background: #fff5f5; }
  code { background: #f1f5f9; padding: 2px 7px; border-radius: 4px; font-size: 12px; color: #475569; }
  .td-actions { display: flex; gap: 6px; }
</style>
</head>
<body> <aside class="sidebar"> <div class="sidebar-head"> <div class="logo">BNDA</div> <div class="sub">ADMINISTRATION</div> </div> <nav class="nav"> <a href="home.php">Tableau de bord</a> <a href="virement.php">Virements</a> <a href="admin.php" class="active">Administration</a> <hr class="nav-divider"> <a href="logout.php">Déconnexion</a> </nav> <div class="sidebar-foot"> <div class="user-info"> <div class="name"><?= e($_SESSION['nom']) ?></div> <div class="role"><?= e($_SESSION['role']) ?></div> </div> </div>
</aside> <main class="main"> <div class="topbar"> <h2> Administration</h2> <div class="secure-badge"> Version sécurisée</div> </div> <div class="content"> <?php if ($msg): ?><div class="alert-ok"> <?= e($msg) ?></div><?php endif; ?> <?php if ($err): ?><div class="alert-err"> <?= e($err) ?></div><?php endif; ?> <!-- ══ FORMULAIRE CRÉER / MODIFIER ══ --> <?php if ($action === 'create' || ($action === 'edit' && $edit_user)): ?> <div class="card"> <div class="card-head"> <h3><?= $action === 'edit' ? ' Modifier l\'utilisateur' : ' Nouvel utilisateur' ?></h3> <a href="admin.php" class="btn btn-cancel"> Annuler</a> </div> <div class="card-body"> <form method="POST"> <!-- CORRECTION CSRF : Token sur chaque formulaire --> <input type="hidden" name="csrf_token" value="<?= csrf() ?>"> <input type="hidden" name="action" value="<?= $action === 'edit' ? 'update' : 'create' ?>"> <?php if ($action === 'edit'): ?> <input type="hidden" name="id" value="<?= (int)$edit_user['id'] ?>"> <?php endif; ?> <div class="grid3"> <div class="form-group"> <label>Nom complet</label> <!-- CORRECTION SQLi : Requête préparée côté serveur --> <input type="text" name="nom"
                     value="<?= e($edit_user['nom'] ?? '') ?>"
                     placeholder="Nom et prénom" required minlength="3" maxlength="100"> </div> <div class="form-group"> <label>Nom d'utilisateur</label> <input type="text" name="username"
                     value="<?= e($edit_user['username'] ?? '') ?>"
                     placeholder="username" required
                     pattern="[a-zA-Z0-9_]{3,50}" title="Lettres, chiffres et _ uniquement"> <span class="hint">Lettres, chiffres, underscore (3-50 caractères)</span> </div> <div class="form-group"> <label>Email</label> <input type="email" name="email"
                     value="<?= e($edit_user['email'] ?? '') ?>"
                     placeholder="email@exemple.com" required maxlength="150"> </div> </div> <div class="grid2" style="margin-top:16px"> <div class="form-group"> <label>Mot de passe<?= $action === 'edit' ? ' (vide = inchangé)' : '' ?></label> <!-- CORRECTION : Mot de passe hashé avec bcrypt, jamais affiché --> <input type="password" name="password"
                     placeholder="<?= $action === 'edit' ? 'Laisser vide pour ne pas changer' : 'Minimum 8 caractères' ?>"
                     <?= $action === 'create' ? 'required minlength="8"' : 'minlength="8"' ?> maxlength="128"> <span class="hint">Minimum 8 caractères — stocké en bcrypt</span> </div> <div class="form-group"> <label>Rôle</label> <select name="role"> <option value="client" <?= (($edit_user['role'] ?? 'client') === 'client') ? 'selected' : '' ?>>Client</option> <option value="admin"  <?= (($edit_user['role'] ?? '') === 'admin')  ? 'selected' : '' ?>>Admin</option> </select> </div> </div> <div class="form-actions"> <button type="submit" class="btn btn-primary"> <?= $action === 'edit' ? ' Enregistrer' : ' Créer l\'utilisateur' ?> </button> <a href="admin.php" class="btn btn-cancel">Annuler</a> </div> </form> </div> </div> <?php endif; ?> <!-- ══ LISTE DES UTILISATEURS ══ --> <div class="card"> <div class="card-head"> <h3> Gestion des utilisateurs</h3> <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap"> <form method="GET" class="search-row"> <!-- CORRECTION SQLi : valeur utilisée dans requête préparée --> <input type="text" name="q" placeholder="Rechercher..." value="<?= e($q) ?>" maxlength="50"> <button type="submit"></button> </form> <a href="admin.php?action=create" class="btn btn-gold">+ Ajouter</a> </div> </div> <table> <thead> <tr> <th>ID</th><th>Nom</th><th>Username</th><th>Email</th> <!-- CORRECTION : Mot de passe JAMAIS affiché --> <th>Rôle</th><th>Créé le</th><th>Actions</th> </tr> </thead> <tbody> <?php foreach ($users as $u): ?> <tr> <td><?= (int)$u['id'] ?></td> <td><?= e($u['nom']) ?></td> <td><code><?= e($u['username']) ?></code></td> <td><?= e($u['email']) ?></td> <td><span class="badge badge-<?= e($u['role']) ?>"><?= e($u['role']) ?></span></td> <td style="color:#64748b;font-size:12px"><?= e($u['created_at']) ?></td> <td> <div class="td-actions"> <a href="admin.php?action=edit&id=<?= (int)$u['id'] ?>" class="btn btn-edit"> Modifier</a> <?php if ($u['role'] !== 'admin'): ?> <!-- CORRECTION CSRF : Suppression via POST + token --> <form method="POST" onsubmit="return confirm('Supprimer cet utilisateur ?')"> <input type="hidden" name="csrf_token" value="<?= csrf() ?>"> <input type="hidden" name="action"  value="delete"> <input type="hidden" name="user_id" value="<?= (int)$u['id'] ?>"> <button type="submit" class="btn btn-danger"> Supprimer</button> </form> <?php else: ?> <span class="badge badge-admin">Protégé</span> <?php endif; ?> </div> </td> </tr> <?php endforeach; ?> </tbody> </table> </div> <!-- ══ COMPTES BANCAIRES ══ --> <div class="card"> <div class="card-head"><h3> Comptes bancaires</h3></div> <table> <thead> <tr><th>ID</th><th>N° Compte</th><th>Client</th><th>Type</th><th>Solde</th><th>Statut</th></tr> </thead> <tbody> <?php foreach ($comptes as $c): ?> <tr> <td><?= (int)$c['id'] ?></td> <td><strong><?= e($c['numero']) ?></strong></td> <td><?= e($c['username']) ?></td> <td><?= e($c['type']) ?></td> <td class="amount"><?= number_format($c['solde'],0,',',' ') ?> FCFA</td> <td><span class="badge badge-actif"><?= e($c['statut']) ?></span></td> </tr> <?php endforeach; ?> </tbody> </table> </div> <!-- ══ LOGS DE SÉCURITÉ ══ --> <div class="card"> <div class="card-head"><h3> Journaux de sécurité (30 derniers)</h3></div> <div class="scroll-table"> <table> <thead> <tr><th>Date</th><th>User ID</th><th>Action</th><th>IP</th><th>Détail</th></tr> </thead> <tbody> <?php foreach ($logs as $l):
              $isDanger = preg_match('/fail|block|csrf|idor|lock/i', $l['action']);
            ?> <tr class="<?= $isDanger ? 'log-danger' : '' ?>"> <td style="font-size:12px;color:#64748b"><?= e($l['date_action']) ?></td> <td><?= $l['user_id'] ? (int)$l['user_id'] : '—' ?></td> <td><span class="badge <?= $isDanger ? 'badge-danger' : 'badge-ok' ?>"><?= e($l['action']) ?></span></td> <td style="font-size:12px"><?= e($l['ip']) ?></td> <td style="font-size:12px;color:#64748b"><?= e($l['detail']) ?></td> </tr> <?php endforeach; ?> </tbody> </table> </div> </div> </div>
</main>
</body>
</html>
