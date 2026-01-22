<?php
/**
 * Module Wall - VULNÉRABLE AU STORED XSS
 * 
 * 🎯 OBJECTIF : Injecter du JavaScript qui s'exécute pour tous les visiteurs
 * 
 * 💡 INDICE : Les messages postés ne sont pas échappés avant affichage...
 *    Le code HTML/JS est interprété tel quel !
 */

$error = null;
$success = null;

// Traitement du nouveau message
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['message'])) {
    $message = $_POST['message'];
    
    if (!empty($message)) {
        // VULNÉRABILITÉ : Le message est stocké tel quel, sans nettoyage !
        $stmt = $db->prepare('INSERT INTO wall_posts (content, author) VALUES (?, ?)');
        $author = isLoggedIn() ? $_SESSION['username'] : 'Anonyme';
        $stmt->execute([$message, $author]);
        
        // Détection de XSS pour afficher le flag
        if (preg_match('/<script|javascript:|onerror|onload|onclick/i', $message)) {
            flash('success', '🏆 XSS détecté ! FLAG : ' . SECRET_XSS);
        } else {
            flash('success', 'Message posté !');
        }
        
        redirect('/wall');
    } else {
        $error = "Le message ne peut pas être vide.";
    }
}

// Récupération des messages
$posts = $db->query('SELECT * FROM wall_posts ORDER BY created_at DESC LIMIT 50')->fetchAll(PDO::FETCH_ASSOC);
?>

<div class="container">
    <div class="module-card">
        <div class="module-header">
            <h1>📝 The Wall</h1>
            <span class="badge badge-danger">Stored XSS</span>
        </div>
        
        <div class="module-hint">
            <h3>💡 Objectif</h3>
            <p>Ce mur de messages est vulnérable au <strong>Cross-Site Scripting (XSS) stocké</strong>.</p>
            <p>Votre mission : Poster un message contenant du JavaScript malveillant.</p>
        </div>
        
        <?php if ($error): ?>
            <div class="alert alert-danger"><?= $error ?></div>
        <?php endif; ?>
        
        <?php if ($success): ?>
            <div class="alert alert-success"><?= $success ?></div>
        <?php endif; ?>
        
        <form method="POST" class="wall-form">
            <div class="form-group">
                <label for="message">Nouveau message</label>
                <textarea id="message" name="message" class="form-control" rows="3" 
                          placeholder="Exprimez-vous..."></textarea>
            </div>
            <button type="submit" class="btn btn-primary">Publier</button>
        </form>
        
        <div class="wall-posts">
            <h3>📜 Messages récents</h3>
            <?php if (empty($posts)): ?>
                <p class="no-posts">Aucun message pour le moment. Soyez le premier !</p>
            <?php else: ?>
                <?php foreach ($posts as $post): ?>
                    <div class="post-card">
                        <div class="post-header">
                            <span class="post-author"><?= htmlspecialchars($post['author']) ?></span>
                            <span class="post-date"><?= $post['created_at'] ?></span>
                        </div>
                        <div class="post-content">
                            <?php 
                            // CORRECTION : Échappement HTML pour prévenir le XSS
                            echo htmlspecialchars($post['content'], ENT_QUOTES, 'UTF-8'); 
                            ?>
                        </div>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>
    </div>
</div>
