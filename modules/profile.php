<?php
/**
 * Module User Bio - VULNÉRABLE À L'IDOR (Insecure Direct Object Reference)
 * 
 * 🎯 OBJECTIF : Accéder au profil de l'administrateur (ID 1)
 * 
 * 💡 INDICE : Le paramètre ?id= dans l'URL n'est pas vérifié...
 *    Vous pouvez voir n'importe quel profil en changeant l'ID !
 */

// VULNÉRABILITÉ : Pas de vérification que l'utilisateur a le droit de voir ce profil
$requestedId = $_GET['id'] ?? null;

// Si pas d'ID spécifié et utilisateur connecté, rediriger vers son propre profil avec l'ID dans l'URL
if ($requestedId === null && isLoggedIn()) {
    header('Location: /profile?id=' . $_SESSION['user_id']);
    exit;
}

$profile = null;
$isOwnProfile = false;

if ($requestedId) {
    // CORRECTION : Vérification de l'autorisation côté serveur
    // L'utilisateur ne peut voir que son propre profil
    if (!isLoggedIn()) {
        die('Accès refusé. Veuillez vous connecter.');
    }
    
    if ($requestedId != $_SESSION['user_id']) {
        die('Accès refusé. Vous ne pouvez voir que votre propre profil.');
    }
    
    $stmt = $db->prepare('SELECT id, username, bio, is_admin FROM users WHERE id = ?');
    $stmt->execute([$requestedId]);
    $profile = $stmt->fetch(PDO::FETCH_ASSOC);
    
    $isOwnProfile = isLoggedIn() && $_SESSION['user_id'] == $requestedId;
}
?>

<div class="container">
    <div class="module-card">
        <div class="module-header">
            <h1>👤 User Bio</h1>
            <span class="badge badge-warning">IDOR</span>
        </div>
        
        <div class="module-hint">
            <h3>💡 Objectif</h3>
            <p>Vous consultez actuellement votre propre profil.</p>
            <p>Votre mission : Trouver un moyen d'accéder au profil de l'administrateur qui contient un secret.</p>
        </div>
        
        <?php if ($profile): ?>
            <div class="profile-card <?= $profile['is_admin'] ? 'admin-profile' : '' ?>">
                <h2>
                    <?= htmlspecialchars($profile['username']) ?>
                    <?php if ($profile['is_admin']): ?>
                        <span class="badge badge-admin">👑 Administrateur</span>
                    <?php endif; ?>
                </h2>
                
                <div class="bio-section">
                    <h4>Biographie :</h4>
                    <p class="bio-content"><?= htmlspecialchars($profile['bio']) ?></p>
                </div>
                
                <?php if ($profile['is_admin'] && !$isOwnProfile): ?>
                    <div class="alert alert-success">
                        <p>🏆 Bravo ! Vous avez accédé au profil admin sans autorisation.</p>
                        <p><strong>FLAG IDOR :</strong> <?= SECRET_IDOR ?></p>
                    </div>
                <?php endif; ?>
            </div>
        <?php else: ?>
            <div class="alert alert-info">
                <p>Aucun profil à afficher.</p>
                <?php if (!isLoggedIn()): ?>
                    <p>Connectez-vous pour voir votre profil.</p>
                <?php endif; ?>
            </div>
        <?php endif; ?>
        
        <div class="info-box">
            <h4>ℹ️ URL actuelle</h4>
            <p><code>/profile<?= isset($_GET['id']) ? '?id=' . htmlspecialchars($_GET['id']) : '' ?></code></p>
        </div>
    </div>
</div>
