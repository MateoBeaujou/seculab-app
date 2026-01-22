<?php
/**
 * Module Auth Gate - VULNÉRABLE À L'INJECTION SQL
 * 
 * 🎯 OBJECTIF : Trouver le flag caché dans la base de données
 * 
 * 💡 INDICE : La requête SQL est construite par concaténation directe...
 *    Que se passe-t-il si on injecte du SQL dans le champ username ?
 *    
 *    Techniques utiles :
 *    - Contournement d'authentification : ' OR 1=1 --
 *    - Extraction de données : UNION SELECT
 */

$error = null;
$success = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    if(in_array($username, ["admin' --", "admin' OR '1'='1", "admin' OR 1=1 --", "admin' OR 1=1"])) {
      $error = "Bien essayé ! Mais non...";   
    } else {
        // CORRECTION : Utilisation de requêtes préparées (PDO)
        // Les données utilisateur sont séparées de la structure SQL
        try {
            $stmt = $db->prepare('SELECT * FROM users WHERE username = ? AND password = ?');
            $hashedPassword = md5($password);
            $stmt->execute([$username, $hashedPassword]);
            $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
            usort($users, fn($a, $b) => $b['id'] - $a['id']); // Tri DESC par ID
            $user = $users[0] ?? null;
            
            if ($user) {
                // Création de la session
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $user['username'];
                $_SESSION['is_admin'] = $user['is_admin'] ?? 0;
                
                flash('success', 'Connexion réussie ! Bienvenue ' . $user['username']);
                
                // Si c'est une injection UNION, afficher le résultat
                if (strpos(strtolower($username), 'union') !== false) {
                    $success = "🏆 FLAG SQL Injection : " . SECRET_SQLI;
                }
                
                redirect('/');
            } else {
                $error = "Identifiants incorrects.";
            }
        } catch (PDOException $e) {
            // Affichage de l'erreur SQL (aide au debug pour l'étudiant)
            $error = "Erreur SQL : " . $e->getMessage();
        }
    }

}
?>

<div class="container">
    <div class="module-card">
        <div class="module-header">
            <h1>🔓 Auth Gate</h1>
            <span class="badge badge-danger">SQL Injection</span>
        </div>
        
        <div class="module-hint">
            <h3>💡 Objectif</h3>
            <p>Ce formulaire de connexion est vulnérable à l'<strong>injection SQL</strong>.</p>
            <p>Votre mission : Contourner l'authentification sans connaître le mot de passe.</p>
            <p class="hint-credentials">Compte ciblé : <code>charlie</code></p>
        </div>
        
        <?php if ($error): ?>
            <div class="alert alert-danger"><?= $error ?></div>
        <?php endif; ?>
        
        <?php if ($success): ?>
            <div class="alert alert-success"><?= $success ?></div>
        <?php endif; ?>
        
        <form method="POST" class="auth-form">
            <div class="form-group">
                <label for="username">Nom d'utilisateur</label>
                <input type="text" id="username" name="username" class="form-control" 
                       placeholder="charlie" value="<?= htmlspecialchars($_POST['username'] ?? '') ?>">
            </div>
            
            <div class="form-group">
                <label for="password">Mot de passe</label>
                <input type="password" id="password" name="password" class="form-control" 
                       placeholder="••••••••">
            </div>
            
            <button type="submit" class="btn btn-primary">Se connecter</button>
        </form>
        
        <?php if (isLoggedIn()): ?>
            <div class="status-box success">
                <p>✅ Vous êtes connecté en tant que <strong><?= htmlspecialchars($_SESSION['username']) ?></strong></p>
            </div>
        <?php endif; ?>
    </div>
</div>
